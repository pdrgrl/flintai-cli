"""
test_elixir_comprehensive.py — Deep verification and edge-case testing for Elixir support.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from flintai.cli.file_filter import (
    FileType,
    find_relevant_files,
    is_relevant_file,
)
from flintai.scan.scorer import (
    map_opengrep_to_taxonomy,
    map_sobelow_to_taxonomy,
)
from flintai.scan.static_scanner import (
    _parse_mix_lock_packages,
    _query_osv_api,
    check_unpinned_mix_dependencies,
    run_mix_audit,
    run_sobelow,
    run_static_scan,
)
from flintai.scan.tool_dispatcher import ToolDispatcher
from flintai.scan.triage import _ANCHOR_PATTERNS
from flintai.schema import RepoFile


class TestElixirFrameworkDiscovery(unittest.TestCase):
    """Test Layer 1 discovery on all Elixir AI framework patterns."""

    def test_framework_detection_variants(self):
        cases = [
            ("alias LangChain.Chains.LLMChain", "LangChain (Elixir)"),
            ("use LangChain.Function", "LangChain (Elixir)"),
            ("import Instructor", "Instructor (Elixir)"),
            ("alias InstructorLite.Instruction", "InstructorLite"),
            ("alias ReqLLM.Client", "ReqLLM"),
            ("alias Bumblebee.Text", "Bumblebee"),
            ("use AnubisMCP.Server", "Anubis MCP (Elixir)"),
            ("alias Complear.MCP.Tool", "Elixir MCP"),
            ("@behaviour Complear.Agents.Specialist", "Elixir Agent Specialist"),
            ("alias Complear.Agents.Engine", "Elixir Agent Specialist"),
            ("use GenServer", "OTP GenServer Agent"),
        ]

        for code, expected_fw in cases:
            with tempfile.TemporaryDirectory() as tmp_dir:
                file_path = os.path.join(tmp_dir, "agent.ex")
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"defmodule TestModule do\n  {code}\nend\n")

                relevant = find_relevant_files(file_path)
                self.assertEqual(len(relevant), 1, f"Failed to detect: {code}")
                self.assertEqual(relevant[0].type, FileType.ELIXIR)
                self.assertEqual(relevant[0].framework, expected_fw)

    def test_ignore_plain_elixir_modules(self):
        code = "defmodule MathUtils do\n  def add(a, b), do: a + b\nend\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = os.path.join(tmp_dir, "utils.ex")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)
            self.assertEqual(find_relevant_files(file_path), [])


class TestElixirManifestsAndDependencies(unittest.TestCase):
    """Test Hex package parsing and OSV querying."""

    def test_parse_complex_mix_lock(self):
        lock_content = """
%{
  "anubis_mcp": {:hex, :anubis_mcp, "1.14.0", "hash1", [:mix], [], "hexpm", "hash2"},
  "langchain": {:hex, :langchain, "0.9.0", "hash3", [:mix], [], "hexpm", "hash4"},
  "pgvector": {:hex, :pgvector, "0.3.0", "hash5", [:mix], [], "hexpm", "hash6"},
  "sobelow": {:hex, :sobelow, "0.13.0", "hash7", [:mix], [], "hexpm", "hash8"},
  "git_dep": {:git, "https://github.com/example/git_dep.git", "branch", []},
}
"""
        packages = _parse_mix_lock_packages(lock_content)
        pkg_map = {p["name"]: p["version"] for p in packages}

        self.assertEqual(len(packages), 4)
        self.assertEqual(pkg_map["anubis_mcp"], "1.14.0")
        self.assertEqual(pkg_map["langchain"], "0.9.0")
        self.assertEqual(pkg_map["pgvector"], "0.3.0")
        self.assertEqual(pkg_map["sobelow"], "0.13.0")
        self.assertNotIn("git_dep", pkg_map)

    def test_check_unpinned_mix_deps_variations(self):
        mix_exs = """
defmodule App.MixProject do
  use Mix.Project
  defp deps do
    [
      {:langchain, ">= 0.8.0"},
      {:instructor, "~> 0.1.0"},
      {:req_llm, ">= 0.1.0"},
      {:jason, "~> 1.4"}
    ]
  end
end
"""
        findings = check_unpinned_mix_dependencies(mix_exs, "mix.exs")
        self.assertEqual(len(findings), 2)
        rules = [f.rule_id for f in findings]
        self.assertTrue(all(r == "unpinned-ai-dependency" for r in rules))
        messages = " ".join([f.message for f in findings])
        self.assertIn("langchain", messages)
        self.assertIn("req_llm", messages)
        self.assertNotIn("jason", messages)

    @patch("urllib.request.urlopen")
    def test_query_osv_api_hex(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-1234-5678-90ab",
                            "aliases": ["CVE-2026-9999"],
                            "summary": "Remote code execution in Hex package",
                            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                        }
                    ]
                }
            ]
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        packages = [{"name": "langchain", "version": "0.1.0"}]
        findings = _query_osv_api(packages, "mix.lock", ecosystem="Hex", tool_name="mix_audit")

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.tool, "mix_audit")
        self.assertEqual(f.rule_id, "CVE-2026-9999")
        self.assertEqual(f.severity, "critical")
        self.assertIn("langchain==0.1.0", f.message)


class TestSobelowIntegration(unittest.TestCase):
    """Test Sobelow parsing and taxonomy mapping."""

    @patch("shutil.which", return_value="/usr/local/bin/sobelow")
    @patch("subprocess.run")
    def test_run_sobelow_parsing(self, mock_run, mock_which):
        mock_sobelow_json = {
            "findings": {
                "high_confidence": [
                    {
                        "type": "RCE.CodeModule",
                        "file": "/tmp/test/lib/agent.ex",
                        "line": 42,
                        "variable": "Code.eval_string(user_input)",
                        "code": "Code.eval_string(user_input)",
                    }
                ],
                "medium_confidence": [
                    {
                        "type": "Traversal.FileModule",
                        "file": "/tmp/test/lib/reader.ex",
                        "line": 15,
                        "variable": "File.read!(path)",
                        "code": "File.read!(path)",
                    }
                ]
            }
        }
        mock_res = MagicMock()
        mock_res.stdout = json.dumps(mock_sobelow_json)
        mock_run.return_value = mock_res

        findings = run_sobelow("/tmp/test")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].rule_id, "RCE.CodeModule")
        self.assertEqual(findings[0].filepath, "lib/agent.ex")
        self.assertEqual(findings[0].line, 42)

        self.assertEqual(findings[1].severity, "medium")
        self.assertEqual(findings[1].rule_id, "Traversal.FileModule")
        self.assertEqual(findings[1].filepath, "lib/reader.ex")
        self.assertEqual(findings[1].line, 15)


class TestTriageAnchorPatterns(unittest.TestCase):
    """Test that Elixir execution primitives match anchor patterns in triage."""

    def test_elixir_anchor_patterns(self):
        elixir_samples = [
            'Code.eval_string(user_code)',
            'Code.eval_quoted(ast)',
            'System.cmd("bash", ["-c", cmd])',
            ':os.cmd(~c"rm -rf /")',
            ':erlang.binary_to_term(data)',
            'String.to_atom(var)',
            '@api_key "sk-proj-1234567890abcdef"',
            'api_key: "sk-proj-1234567890abcdef"',
        ]

        for sample in elixir_samples:
            matched = any(pattern.search(sample) for pattern in _ANCHOR_PATTERNS)
            self.assertTrue(matched, f"Anchor pattern failed to match: '{sample}'")


class TestToolDispatcherElixirImports(unittest.TestCase):
    """Test AST/regex import resolution for Elixir modules."""

    def test_nested_module_resolution(self):
        files = {
            "lib/complear/agents/engine/lang_chain_engine.ex": RepoFile(
                path="lib/complear/agents/engine/lang_chain_engine.ex",
                content="""
defmodule Complear.Agents.Engine.LangChainEngine do
  alias Complear.Agents.Specialist
  alias LangChain.Chains.LLMChain
  require Logger
end
""",
                size=200,
            ),
            "lib/complear/agents/specialist.ex": RepoFile(
                path="lib/complear/agents/specialist.ex",
                content="defmodule Complear.Agents.Specialist do\nend\n",
                size=100,
            ),
        }

        dispatcher = ToolDispatcher(repo_files=files, agents=[], static_findings=[])
        result = dispatcher._resolve_imports("lib/complear/agents/engine/lang_chain_engine.ex")

        self.assertIn("Complear.Agents.Specialist", result)
        self.assertIn("IN REPO", result)
        self.assertIn("LangChain.Chains.LLMChain", result)
        self.assertIn("external package", result)


if __name__ == "__main__":
    unittest.main()
