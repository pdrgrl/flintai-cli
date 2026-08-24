"""
static_scanner.py — Layer 2b: Open-Source Static Analysis
Runs Bandit, detect-secrets, pip-audit, and custom OpenGrep rules
against the fetched repository files.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

import yaml

from ..schema import RepoFile
from .opengrep_resolver import find_opengrep_binary
from .schema import PackageInfo

logger = logging.getLogger(__name__)

# Use sys.executable so the current Python interpreter finds installed
# packages rather than looking for CLI tools on the system PATH.
_PY = sys.executable


@dataclass
class StaticFinding:
    tool: str  # bandit | opengrep | detect_secrets | pip_audit | internal
    rule_id: str
    severity: str
    message: str
    filepath: str
    line: int = 0
    evidence: str = ""
    cwe: str = ""


@dataclass
class SkippedTool:
    """A tool that could not run, and why."""

    tool: str
    reason: str


@dataclass
class StaticScanResult:
    """
    Findings plus a record of which tools actually contributed them.

    A skipped tool means the scan is *partial* — callers are expected to
    surface this rather than report a clean result.

    Callers writing `tools_skipped` into `ScanReport.scan_metadata` must
    convert with `dataclasses.asdict` first: the SARIF formatter passes
    `scan_metadata` straight to `json.dumps` without an `asdict` pass, so a
    dataclass instance left in there raises `TypeError` at output time.
    """

    findings: list[StaticFinding]
    tools_used: list[str]
    tools_skipped: list[SkippedTool]


_OPENGREP_RULES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config", "agent_opengrep_rules.yaml"
)


def _load_opengrep_rules() -> str:
    with open(_OPENGREP_RULES_PATH, encoding="utf-8") as f:
        return f.read()


def _module_available(module: str) -> bool:
    """
    Whether a Python-packaged tool is importable.

    Bandit and pip-audit are dispatched as `sys.executable -m <module>`, so
    an absent package is not an exception — the subprocess just exits
    non-zero with an empty stdout, which is indistinguishable from a clean
    scan. `find_spec` is the `shutil.which` of that dispatch: it answers for
    the very interpreter the subprocess will run.
    """
    try:
        return importlib.util.find_spec(module) is not None
    except Exception as e:  # a broken package must not break the scan
        logger.warning("Could not resolve the %s module: %s", module, e)
        return False


_BANDIT_SKIP_REASON = (
    "Bandit is not installed. Skipped the generic Python security checks; "
    "scan coverage is incomplete. Install with `pip install bandit`."
)

_DETECT_SECRETS_SKIP_REASON = (
    "detect-secrets is not installed. Skipped the hardcoded-credential scan "
    "; scan coverage is incomplete. Install with `pip install detect-secrets`."
)

_PIP_AUDIT_SKIP_REASON = (
    "pip-audit is not installed. Skipped dependencies analysis; scan coverage "
    "is incomplete. Install with `pip install pip-audit`."
)


def _opengrep_skip_reason() -> str:
    """Built at call time so the rule count comes from the rules file."""
    try:
        parsed = yaml.safe_load(_load_opengrep_rules()) or {}
        count = len(parsed.get("rules") or [])
    except Exception as e:  # a malformed rules file must not break the scan
        logger.warning("Could not count OpenGrep agent rules: %s", e)
        count = 0
    rules = (
        f"{count} agent-specific rule{'' if count == 1 else 's'}"
        if count
        else "the agent-specific rules"
    )
    return (
        f"OpenGrep binary not found. Skipped {rules}; scan coverage is "
        "incomplete. Install from https://github.com/opengrep/opengrep/releases."
    )


# ── Severity mapping ─────────────────────────────────────────────────────────

BANDIT_SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

OPENGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


# ── Static analysis runners ──────────────────────────────────────────────────


def run_bandit(files_dir: str) -> list[StaticFinding]:
    """Run Bandit on Python files and parse findings."""
    findings = []
    if not _module_available("bandit"):
        logger.warning("Skipping Bandit scan. %s", _BANDIT_SKIP_REASON)
        return findings
    try:
        result = subprocess.run(
            [
                _PY,
                "-m",
                "bandit",
                "-r",
                files_dir,
                "-f",
                "json",
                "-q",
                "--severity-level",
                "low",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if not result.stdout.strip():
            return findings

        data = json.loads(result.stdout)
        for issue in data.get("results", []):
            rel_path = issue.get("filename", "").replace(files_dir, "").lstrip("/\\")
            findings.append(
                StaticFinding(
                    tool="bandit",
                    rule_id=issue.get("test_id", ""),
                    severity=BANDIT_SEVERITY_MAP.get(
                        issue.get("issue_severity", "LOW"), "low"
                    ),
                    message=issue.get("issue_text", ""),
                    filepath=rel_path,
                    line=issue.get("line_number", 0),
                    evidence=issue.get("code", "")[:200],
                    cwe=issue.get("issue_cwe", {}).get("id", ""),
                )
            )
    except Exception as e:
        logger.error("Bandit error: %s", e)

    return findings


def run_opengrep(files_dir: str, rules_file: str) -> list[StaticFinding]:
    """Run OpenGrep with custom agent rules and parse findings."""
    findings = []
    opengrep_bin = find_opengrep_binary()
    if not opengrep_bin:
        logger.warning("Skipping OpenGrep pattern scan. %s", _opengrep_skip_reason())
        return findings
    try:
        result = subprocess.run(
            [
                opengrep_bin,
                "scan",
                "--config",
                rules_file,
                files_dir,
                "--json",
                "--quiet",
                "--no-git-ignore",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        # OpenGrep writes JSON to stdout on success (exit 0) and on
        # findings-found (exit 1). On rule errors (exit 7) it may
        # write to stderr instead. Try both.
        raw_json = result.stdout.strip() or result.stderr.strip()
        if not raw_json:
            return findings

        data = json.loads(raw_json)
        for err in data.get("errors", []):
            logger.warning("OpenGrep rule error: %s", err)
        for issue in data.get("results", []):
            rel_path = issue.get("path", "").replace(files_dir, "").lstrip("/\\")
            findings.append(
                StaticFinding(
                    tool="opengrep",
                    rule_id=issue.get("check_id", ""),
                    severity=OPENGREP_SEVERITY_MAP.get(
                        issue.get("extra", {}).get("severity", "INFO"), "low"
                    ),
                    message=issue.get("extra", {}).get("message", ""),
                    filepath=rel_path,
                    line=issue.get("start", {}).get("line", 0),
                    evidence=issue.get("extra", {}).get("lines", "")[:200],
                )
            )
    except Exception as e:
        logger.error("OpenGrep error: %s", e)

    return findings


def run_detect_secrets(files_dir: str) -> list[StaticFinding]:
    """Run detect-secrets to find hardcoded credentials."""
    findings = []
    if not _module_available("detect_secrets"):
        logger.warning("Skipping detect-secrets scan. %s", _DETECT_SECRETS_SKIP_REASON)
        return findings
    try:
        result = subprocess.run(
            [_PY, "-m", "detect_secrets", "scan", files_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if not result.stdout.strip():
            return findings

        data = json.loads(result.stdout)
        for filepath, secrets in data.get("results", {}).items():
            rel_path = filepath.replace(files_dir, "").lstrip("/\\")
            for secret in secrets:
                findings.append(
                    StaticFinding(
                        tool="detect_secrets",
                        rule_id=secret.get("type", "secret"),
                        severity="high",
                        message=f"Potential secret detected: {secret.get('type', 'unknown')}",
                        filepath=rel_path,
                        line=secret.get("line_number", 0),
                        evidence=f"[redacted — line {secret.get('line_number', '?')}]",
                    )
                )
    except Exception as e:
        logger.error("detect-secrets error: %s", e)

    return findings


def _parse_pinned_packages(requirements_content: str) -> list[PackageInfo]:
    """
    Parse a requirements.txt and return a list of {name, version} dicts
    for all pinned (==) packages. Skips comments, blank lines, and unpinned entries.
    """
    packages = []
    for line in requirements_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            # Strip inline comments
            line = line.split("#")[0].strip()
            parts = line.split("==")
            if len(parts) == 2:
                name = parts[0].strip()
                version = parts[1].strip().split()[0]  # strip any trailing extras
                if name and version:
                    packages.append({"name": name, "version": version})
    return packages


def _query_osv_api(
    packages: list[PackageInfo],
    filepath: str,
    ecosystem: str = "PyPI",
    tool_name: str = "pip_audit",
) -> list[StaticFinding]:
    """
    Query the OSV.dev batch API directly for a list of {name, version} packages.
    No virtual env, no package installation, no language version constraints.
    Supports PyPI, Hex, npm, etc.
    Docs: https://osv.dev/docs/#tag/api/operation/OSV_QueryAffectedBatch
    """
    findings = []
    if not packages:
        return findings

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    payload = {
        "queries": [
            {
                "version": pkg["version"],
                "package": {"name": pkg["name"], "ecosystem": ecosystem},
            }
            for pkg in packages
        ]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            response = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        logger.error("OSV API request failed: %s", e)
        return findings
    except Exception as e:
        logger.error("OSV API error: %s", e)
        return findings

    results = response.get("results", [])
    vuln_count = 0
    for i, result in enumerate(results):
        if i >= len(packages):
            break
        pkg = packages[i]
        vulns = result.get("vulns", [])
        for vuln in vulns:
            vuln_count += 1
            # Derive severity from CVSS score if available, else default to high
            severity = "high"
            cvss_score = None
            for severity_entry in vuln.get("severity", []):
                if severity_entry.get("type") == "CVSS_V3":
                    raw_score = severity_entry.get("score", 0)
                    # OSV may return a CVSS vector string instead of a numeric score
                    if isinstance(raw_score, str) and raw_score.startswith("CVSS:"):
                        break
                    try:
                        score = float(raw_score)
                        cvss_score = score  # noqa: F841
                        if score >= 9.0:
                            severity = "critical"
                        elif score >= 7.0:
                            severity = "high"
                        elif score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                    except (ValueError, TypeError):
                        pass
                    break

            vuln_id = vuln.get("id", "")
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
            summary = vuln.get("summary", "") or vuln.get("details", "")[:200]

            findings.append(
                StaticFinding(
                    tool=tool_name,
                    rule_id=cve_id or vuln_id,
                    severity=severity,
                    message=(f"{pkg['name']}=={pkg['version']}: {summary[:200]}"),
                    filepath=filepath,
                    line=0,
                    evidence=(
                        f"Package: {pkg['name']} {pkg['version']} | "
                        f"ID: {vuln_id} | "
                        f"Aliases: {', '.join(aliases[:3]) if aliases else 'none'}"
                    ),
                )
            )

    logger.info(
        "OSV (%s): %d CVE(s) found across %d of %d packages",
        ecosystem,
        vuln_count,
        len([p for p in results if p.get("vulns")]),
        len(packages),
    )
    return findings


def run_pip_audit(requirements_files: list) -> list[StaticFinding]:
    """
    Scan Python requirements files for known CVEs.
    Strategy:
      1. Try pip-audit (fast, uses local pip resolver)
      2. If pip-audit is not installed, fall back to querying the OSV.dev
         batch API directly.
    """
    findings = []
    pip_audit_available = _module_available("pip_audit")
    if not pip_audit_available:
        logger.warning("Skipping pip-audit. %s", _PIP_AUDIT_SKIP_REASON)

    for req_file_path in requirements_files:
        if not req_file_path.endswith(".txt"):
            continue

        pip_audit_succeeded = False
        if pip_audit_available:
            try:
                result = subprocess.run(
                    [
                        _PY,
                        "-m",
                        "pip_audit",
                        "-r",
                        req_file_path,
                        "--format",
                        "json",
                        "-s",
                        "osv",
                        "--progress-spinner",
                        "off",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode <= 1:
                    stdout = result.stdout.strip()
                    if stdout:
                        data = json.loads(stdout)
                        dependencies = (
                            data
                            if isinstance(data, list)
                            else data.get("dependencies", [])
                        )
                        vuln_count = 0
                        for dep in dependencies:
                            for vuln in dep.get("vulns", []):
                                vuln_count += 1
                                findings.append(
                                    StaticFinding(
                                        tool="pip_audit",
                                        rule_id=vuln.get("id", ""),
                                        severity="high",
                                        message=(
                                            f"{dep.get('name')}=={dep.get('version')}: "
                                            f"{vuln.get('description', '')[:200]}"
                                        ),
                                        filepath=req_file_path,
                                        line=0,
                                        evidence=(
                                            f"Package: {dep.get('name')} {dep.get('version')} | "
                                            f"CVE/ID: {vuln.get('id', 'N/A')} | "
                                            f"Fix: {vuln.get('fix_versions', [])}"
                                        ),
                                    )
                                )
                        logger.info(
                            "pip-audit: %d CVE(s) found in %s",
                            vuln_count,
                            req_file_path.split("/")[-1],
                        )
                        pip_audit_succeeded = True
                    else:
                        stderr_preview = result.stderr.strip()[:200]
                        logger.warning(
                            "pip-audit: empty output — falling back to OSV API. Reason: %s",
                            stderr_preview,
                        )
                else:
                    stderr_preview = result.stderr.strip()[:200]
                    logger.warning(
                        "pip-audit exited %d — falling back to OSV API. Reason: %s",
                        result.returncode,
                        stderr_preview,
                    )

            except json.JSONDecodeError as e:
                logger.warning(
                    "pip-audit JSON parse error — falling back to OSV API: %s", e
                )
            except Exception as e:
                logger.warning("pip-audit error — falling back to OSV API: %s", e)

        # ── Attempt 2: OSV.dev direct API fallback ───────────────────────────────
        if not pip_audit_succeeded:
            try:
                content = open(req_file_path, encoding="utf-8").read()
                packages = _parse_pinned_packages(content)
                if packages:
                    logger.info(
                        "OSV fallback: querying %d pinned packages from %s...",
                        len(packages),
                        req_file_path.split("/")[-1],
                    )
                    findings.extend(
                        _query_osv_api(
                            packages,
                            req_file_path,
                            ecosystem="PyPI",
                            tool_name="pip_audit",
                        )
                    )
                else:
                    logger.info(
                        "OSV fallback: no pinned packages found in %s",
                        req_file_path.split("/")[-1],
                    )
            except Exception as e:
                logger.error("OSV fallback error: %s", e)

    return findings


def _parse_mix_lock_packages(content: str) -> list[PackageInfo]:
    """Extract pinned Hex packages from mix.lock."""
    packages = []
    # Pattern matching "pkg_name": {:hex, :pkg_name, "version", ...}
    pattern = re.compile(
        r'"([a-zA-Z0-9_]+)":\s*\{:hex,\s*:[a-zA-Z0-9_]+,\s*"([0-9a-zA-Z.\-+]+)"'
    )
    for match in pattern.finditer(content):
        name, version = match.group(1), match.group(2)
        packages.append({"name": name, "version": version})
    return packages


def check_unpinned_mix_dependencies(
    mix_exs_content: str, filepath: str
) -> list[StaticFinding]:
    """Check for unpinned AI framework dependencies in mix.exs."""
    findings = []
    ai_packages = {
        "langchain",
        "instructor",
        "instructor_lite",
        "req_llm",
        "bumblebee",
        "anubis_mcp",
        "openai_ex",
        "anthropic",
    }
    pattern = re.compile(r'\{:([a-zA-Z0-9_]+),\s*["\']([^"\']+)["\']')
    for line in mix_exs_content.splitlines():
        line_s = line.strip()
        if not line_s or line_s.startswith("#"):
            continue
        match = pattern.search(line_s)
        if match:
            pkg, req = match.group(1).lower(), match.group(2).strip()
            if pkg in ai_packages:
                if ">=" in req:
                    findings.append(
                        StaticFinding(
                            tool="internal",
                            rule_id="unpinned-ai-dependency",
                            severity="medium",
                            message=f"Unpinned AI framework dependency in mix.exs: '{line_s}' — supply chain risk",
                            filepath=filepath,
                            line=0,
                            evidence=line_s,
                        )
                    )
    return findings


def run_mix_audit(mix_paths: list[str]) -> list[StaticFinding]:
    """Scan Elixir mix.lock files for known CVEs via OSV.dev Hex ecosystem API."""
    findings = []
    for mix_file_path in mix_paths:
        if os.path.basename(mix_file_path) == "mix.lock":
            try:
                content = open(mix_file_path, encoding="utf-8").read()
                packages = _parse_mix_lock_packages(content)
                if packages:
                    logger.info(
                        "Auditing %d Hex packages from %s via OSV API...",
                        len(packages),
                        mix_file_path.split("/")[-1],
                    )
                    findings.extend(
                        _query_osv_api(
                            packages,
                            mix_file_path,
                            ecosystem="Hex",
                            tool_name="mix_audit",
                        )
                    )
            except Exception as e:
                logger.error("Hex package audit error: %s", e)
    return findings


def find_sobelow_binary() -> str | None:
    """Locate sobelow binary in PATH."""
    import shutil

    return shutil.which("sobelow")


def run_sobelow(files_dir: str) -> list[StaticFinding]:
    """Run Sobelow static security analysis on Elixir files and parse findings."""
    findings = []
    sobelow_bin = find_sobelow_binary()
    if not sobelow_bin:
        return findings

    try:
        result = subprocess.run(
            [sobelow_bin, "--format", "json", "--root", files_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw_json = result.stdout.strip()
        if not raw_json:
            return findings

        data = json.loads(raw_json)
        findings_dict = data.get("findings", data)
        for conf, items in findings_dict.items():
            if not isinstance(items, list):
                continue
            severity = (
                "high"
                if "high" in conf.lower()
                else ("medium" if "med" in conf.lower() else "low")
            )
            for item in items:
                if not isinstance(item, dict):
                    continue
                type_name = item.get("type", "Sobelow finding")
                file_path = item.get("file", "").replace(files_dir, "").lstrip("/\\")
                line_num = item.get("line", 0)
                findings.append(
                    StaticFinding(
                        tool="sobelow",
                        rule_id=type_name,
                        severity=severity,
                        message=f"{type_name}: {item.get('variable', '') or item.get('vuln', '')}",
                        filepath=file_path,
                        line=line_num,
                        evidence=str(item.get("code", ""))[:200],
                    )
                )
    except Exception as e:
        logger.warning("Sobelow scan error: %s", e)

    return findings


def check_unpinned_dependencies(
    requirements_content: str, filepath: str
) -> list[StaticFinding]:
    """Check for unpinned AI framework dependencies."""
    findings = []
    ai_packages = [
        "crewai",
        "autogen",
        "pyautogen",
        "langchain",
        "openai",
        "anthropic",
        "langgraph",
        "ag2",
        "autogen-agentchat",
    ]

    for line in requirements_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg_name = re.split(r"[>=<!~\s]", line)[0].lower()
        if pkg_name in ai_packages:
            # Check if pinned (==) or unpinned (>=, ~=, no version)
            if "==" not in line:
                findings.append(
                    StaticFinding(
                        tool="internal",
                        rule_id="unpinned-ai-dependency",
                        severity="medium",
                        message=f"Unpinned AI framework dependency: '{line}' — supply chain risk",  # noqa: B950
                        filepath=filepath,
                        line=0,
                        evidence=line,
                    )
                )

    return findings


# ── Main static scanner entry point ─────────────────────────────────────────


def run_static_scan(
    source_files: list[RepoFile],
    requirements_files: list[RepoFile],
    tmp_dir: str,
) -> StaticScanResult:
    """
    Write source and manifest files to temp dir and run static analysis tools.

    Supports both Python (.py) and Elixir (.ex, .exs, mix.exs, mix.lock) files.
    """
    all_findings = []
    tools_used: list[str] = []
    tools_skipped: list[SkippedTool] = []

    # Separate python and elixir files
    py_files = [f for f in source_files if f.path.endswith(".py")]
    elixir_files = [
        f for f in source_files if f.path.endswith((".ex", ".exs"))
    ]

    # Write source files to disk preserving original relative paths.
    src_dir = os.path.join(tmp_dir, "src")
    os.makedirs(src_dir, exist_ok=True)

    for repo_file in source_files:
        dest = os.path.join(src_dir, repo_file.path.lstrip(os.sep))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(repo_file.content)

    # Write OpenGrep rules
    rules_path = os.path.join(tmp_dir, "agent_rules.yaml")
    with open(rules_path, "w") as f:
        f.write(_load_opengrep_rules())

    # Write requirements & manifest files preserving original paths.
    req_dir = os.path.join(tmp_dir, "reqs")
    os.makedirs(req_dir, exist_ok=True)
    req_paths = []
    mix_paths = []

    for repo_file in requirements_files:
        dest = os.path.join(req_dir, repo_file.path.lstrip(os.sep))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(repo_file.content)

        if repo_file.path.endswith(".txt"):
            req_paths.append(dest)
            all_findings.extend(
                check_unpinned_dependencies(repo_file.content, repo_file.path)
            )
        elif repo_file.path.endswith("mix.exs"):
            mix_paths.append(dest)
            all_findings.extend(
                check_unpinned_mix_dependencies(repo_file.content, repo_file.path)
            )
        elif repo_file.path.endswith("mix.lock"):
            mix_paths.append(dest)

    # 1. Bandit (Python only)
    if py_files:
        if _module_available("bandit"):
            logger.info("Running Bandit on %d Python files...", len(py_files))
            all_findings.extend(run_bandit(src_dir))
            tools_used.append("bandit")
        else:
            logger.warning("Skipping Bandit scan. %s", _BANDIT_SKIP_REASON)
            tools_skipped.append(
                SkippedTool(tool="bandit", reason=_BANDIT_SKIP_REASON)
            )

    # 2. Sobelow (Elixir only)
    if elixir_files:
        sobelow_bin = find_sobelow_binary()
        if sobelow_bin:
            logger.info("Running Sobelow on %d Elixir files...", len(elixir_files))
            all_findings.extend(run_sobelow(src_dir))
            tools_used.append("sobelow")

    # 3. OpenGrep (Multi-language agent rules)
    if find_opengrep_binary():
        logger.info("Running OpenGrep with custom agent rules...")
        all_findings.extend(run_opengrep(src_dir, rules_path))
        tools_used.append("opengrep")
    else:
        skip_reason = _opengrep_skip_reason()
        logger.warning("Skipping OpenGrep pattern scan. %s", skip_reason)
        tools_skipped.append(SkippedTool(tool="opengrep", reason=skip_reason))

    # 4. detect-secrets (All source files)
    if _module_available("detect_secrets"):
        logger.info("Running detect-secrets on %d files...", len(source_files))
        all_findings.extend(run_detect_secrets(src_dir))
        tools_used.append("detect-secrets")
    else:
        logger.warning(
            "Skipping detect-secrets scan. %s", _DETECT_SECRETS_SKIP_REASON
        )
        tools_skipped.append(
            SkippedTool(tool="detect-secrets", reason=_DETECT_SECRETS_SKIP_REASON)
        )

    # 5. pip-audit (Python dependencies)
    if req_paths:
        pip_audit_available = _module_available("pip_audit")
        if pip_audit_available:
            logger.info(
                "Running pip-audit on %d requirements files...", len(req_paths)
            )
        else:
            tools_skipped.append(
                SkippedTool(tool="pip-audit", reason=_PIP_AUDIT_SKIP_REASON)
            )
        pip_findings = run_pip_audit(req_paths)
        for f in pip_findings:
            f.filepath = f.filepath.replace(req_dir, "").lstrip("/\\")
        all_findings.extend(pip_findings)
        tools_used.append("pip-audit" if pip_audit_available else "osv")

    # 6. mix-audit (Elixir dependencies via OSV Hex API)
    if mix_paths:
        hex_findings = run_mix_audit(mix_paths)
        for f in hex_findings:
            f.filepath = f.filepath.replace(req_dir, "").lstrip("/\\")
        all_findings.extend(hex_findings)
        tools_used.append("hex-audit")

    logger.info("Total static findings: %d", len(all_findings))
    return StaticScanResult(
        findings=all_findings,
        tools_used=tools_used,
        tools_skipped=tools_skipped,
    )

