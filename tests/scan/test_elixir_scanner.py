"""
test_elixir_scanner.py — Unit tests for Elixir static analysis and AST tools.
"""

import tempfile
import unittest

from flintai.schema import RepoFile
from flintai.scan.scorer import map_opengrep_to_taxonomy, map_sobelow_to_taxonomy
from flintai.scan.static_scanner import (
    _parse_mix_lock_packages,
    check_unpinned_mix_dependencies,
    run_static_scan,
)
from flintai.scan.tool_dispatcher import ToolDispatcher


class TestElixirStaticScanner(unittest.TestCase):
    def test_parse_mix_lock_packages(self):
        lock_content = """
%{
  "anubis_mcp": {:hex, :anubis_mcp, "1.14.0", "hash1", [:mix], [], "hexpm", "hash2"},
  "langchain": {:hex, :langchain, "0.9.0", "hash3", [:mix], [], "hexpm", "hash4"},
  "req": {:hex, :req, "0.5.0", "hash5", [:mix], [], "hexpm", "hash6"},
  "cabbage": {:git, "https://github.com/cabbage-ex/cabbage", "hash7", []}
}
"""
        packages = _parse_mix_lock_packages(lock_content)
        names = {p["name"] for p in packages}
        versions = {p["name"]: p["version"] for p in packages}

        self.assertIn("anubis_mcp", names)
        self.assertIn("langchain", names)
        self.assertIn("req", names)
        self.assertEqual(versions["anubis_mcp"], "1.14.0")
        self.assertEqual(versions["langchain"], "0.9.0")
        self.assertNotIn("cabbage", names)

    def test_check_unpinned_mix_dependencies(self):
        mix_exs = """
defmodule MyApp.MixProject do
  use Mix.Project

  defp deps do
    [
      {:langchain, ">= 0.1.0"},
      {:instructor, "~> 0.1.0"},
      {:req, "~> 0.5.0"}
    ]
  end
end
"""
        findings = check_unpinned_mix_dependencies(mix_exs, "mix.exs")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "unpinned-ai-dependency")
        self.assertIn("langchain", findings[0].message)

    def test_map_sobelow_to_taxonomy(self):
        self.assertEqual(
            map_sobelow_to_taxonomy("RCE.CodeModule"),
            ("asi05_unexpected_code_execution", "arbitrary_code_execution"),
        )
        self.assertEqual(
            map_sobelow_to_taxonomy("Traversal.FileModule"),
            ("asi02_tool_misuse", "path_traversal"),
        )
        self.assertEqual(
            map_sobelow_to_taxonomy("Config.HTTPS"),
            ("asi03_identity_privilege_abuse", "missing_auth_on_endpoint"),
        )
        self.assertEqual(
            map_sobelow_to_taxonomy("Config.Secrets"),
            ("asi03_identity_privilege_abuse", "hardcoded_credentials"),
        )
        self.assertEqual(
            map_sobelow_to_taxonomy("Misc.BinToTerm"),
            ("asi05_unexpected_code_execution", "unsafe_deserialization"),
        )

    def test_map_elixir_opengrep_to_taxonomy(self):
        self.assertEqual(
            map_opengrep_to_taxonomy("elixir-prompt-interpolation"),
            ("asi01_agent_goal_hijack", "direct_prompt_injection"),
        )
        self.assertEqual(
            map_opengrep_to_taxonomy("elixir-code-eval"),
            ("asi05_unexpected_code_execution", "arbitrary_code_execution"),
        )
        self.assertEqual(
            map_opengrep_to_taxonomy("elixir-system-cmd"),
            ("asi05_unexpected_code_execution", "arbitrary_code_execution"),
        )
        self.assertEqual(
            map_opengrep_to_taxonomy("elixir-atom-exhaustion"),
            ("asi06_memory_context_poisoning", "memory_poisoning"),
        )
        self.assertEqual(
            map_opengrep_to_taxonomy("elixir-mcp-unbounded-tools"),
            ("asi02_tool_misuse", "excessive_tool_permissions"),
        )


class TestElixirToolDispatcher(unittest.TestCase):
    def test_resolve_elixir_imports(self):
        files = {
            "lib/agent.ex": RepoFile(
                path="lib/agent.ex",
                content="""
defmodule MyApp.Agent do
  alias MyApp.Tools.WeatherTool
  alias LangChain.Chains.LLMChain
  use GenServer
end
""",
                size=120,
            ),
            "lib/tools/weather_tool.ex": RepoFile(
                path="lib/tools/weather_tool.ex",
                content="defmodule MyApp.Tools.WeatherTool do\nend\n",
                size=50,
            ),
        }

        dispatcher = ToolDispatcher(repo_files=files, agents=[], static_findings=[])
        result = dispatcher._resolve_imports("lib/agent.ex")

        self.assertIn("MyApp.Tools.WeatherTool", result)
        self.assertIn("IN REPO", result)
        self.assertIn("LangChain.Chains.LLMChain", result)
        self.assertIn("external package", result)


class TestElixirRunStaticScan(unittest.TestCase):
    def test_run_static_scan_with_elixir_files(self):
        source_files = [
            RepoFile(
                path="lib/agent.ex",
                content="""
defmodule Agent do
  alias LangChain.Chains.LLMChain
  def run(input) do
    LLMChain.add_message(Message.new_user!("Hello #{input}"))
  end
end
""",
                size=100,
            )
        ]
        manifest_files = [
            RepoFile(
                path="mix.exs",
                content="""
defmodule Agent.MixProject do
  use Mix.Project
  defp deps do
    [{:langchain, ">= 0.9.0"}]
  end
end
""",
                size=80,
            )
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = run_static_scan(source_files, manifest_files, tmp_dir)
            self.assertIsInstance(result.findings, list)
            # Check that unpinned dependency is flagged
            unpinned = [f for f in result.findings if f.rule_id == "unpinned-ai-dependency"]
            self.assertTrue(len(unpinned) >= 1)


if __name__ == "__main__":
    unittest.main()
