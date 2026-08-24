import ast
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum

from flintai.scan.constants import (
    ELIXIR_FILE_EXTENSIONS,
    ELIXIR_MANIFEST_NAMES,
    REQUIREMENT_FILE_NAMES,
)

logger = logging.getLogger(__name__)

REQUIREMENTS_FILES = tuple(f.lower() for f in REQUIREMENT_FILE_NAMES)
PYTHON_EXTENSIONS = ".py"
PYTHON_IGNORES = "__init__.py"
ELIXIR_EXTENSIONS = ELIXIR_FILE_EXTENSIONS

# Import module root -> Framework name (Python and Elixir)
FRAMEWORK_ROOTS: dict[str, str] = {
    # Python
    "google.adk": "Google ADK",
    "google.genai": "Google GenAI",
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "agents": "OpenAI Agents SDK",
    "langgraph": "LangGraph",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "transformers": "HuggingFace Transformers",
    "smolagents": "HuggingFace smolagents",
    # Elixir
    "LangChain": "LangChain (Elixir)",
    "langchain": "LangChain (Elixir)",
    "Instructor": "Instructor (Elixir)",
    "instructor": "Instructor (Elixir)",
    "InstructorLite": "InstructorLite",
    "instructor_lite": "InstructorLite",
    "ReqLLM": "ReqLLM",
    "req_llm": "ReqLLM",
    "AnubisMCP": "Anubis MCP (Elixir)",
    "anubis_mcp": "Anubis MCP (Elixir)",
    "Complear.MCP": "Elixir MCP",
    "Complear.Agents": "Elixir Agent Specialist",
    "Bumblebee": "Bumblebee",
    "bumblebee": "Bumblebee",
    "OpenAI": "OpenAI (Elixir)",
    "openai_ex": "OpenAI (Elixir)",
    "Anthropic": "Anthropic (Elixir)",
}

ELIXIR_FRAMEWORK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:alias|import|use)\s+LangChain\b"), "LangChain (Elixir)"),
    (re.compile(r"(?:alias|import|use)\s+InstructorLite\b"), "InstructorLite"),
    (re.compile(r"(?:alias|import|use)\s+Instructor\b"), "Instructor (Elixir)"),
    (re.compile(r"(?:alias|import|use)\s+ReqLLM\b"), "ReqLLM"),
    (re.compile(r"(?:alias|import|use)\s+Bumblebee\b"), "Bumblebee"),
    (re.compile(r"(?:alias|import|use)\s+AnubisMCP\b"), "Anubis MCP (Elixir)"),
    (re.compile(r"(?:alias|import|use)\s+Complear\.MCP\b"), "Elixir MCP"),
    (re.compile(r"@behaviour\s+.*Specialist\b"), "Elixir Agent Specialist"),
    (re.compile(r"(?:alias|import|use)\s+Complear\.Agents\b"), "Elixir Agent Specialist"),
    (re.compile(r"use\s+GenServer\b"), "OTP GenServer Agent"),
]



class FileType(Enum):
    PYTHON = "python"
    ELIXIR = "elixir"
    REQUIREMENTS = "requirements"
    OTHER = "other"


@dataclass
class RelevantFile:
    path: str
    type: FileType
    evidence: str | None = None
    framework: str | None = None


def _detect_relevant_file(
    abs_file_path: str,
) -> RelevantFile | None:
    """Detects relevant files for scanning."""
    base_name = os.path.basename(abs_file_path).lower()
    if base_name in REQUIREMENTS_FILES:
        logger.info("File in scope: %s", abs_file_path)
        return RelevantFile(path=abs_file_path, type=FileType.REQUIREMENTS)
    elif abs_file_path.endswith(PYTHON_EXTENSIONS) and not abs_file_path.endswith(
        PYTHON_IGNORES
    ):
        match = _detect_framework_in_file(abs_file_path)
        if match:
            logger.info("File in scope: %s", abs_file_path)
            return match
    elif abs_file_path.endswith(ELIXIR_EXTENSIONS):
        match = _detect_framework_in_elixir_file(abs_file_path)
        if match:
            logger.info("File in scope: %s", abs_file_path)
            return match
    return None


def find_relevant_files(path: str) -> list[RelevantFile]:
    """`path` might be a file or a directory.
    If it is a file, detect its type, if it is a directory,
    recursively find relevant files in the given directory."""
    relevant_files = []

    path = os.path.abspath(path)
    if os.path.isfile(path):
        relevant_file = _detect_relevant_file(path)
        if relevant_file:
            relevant_files.append(relevant_file)
    else:
        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                relevant_file = _detect_relevant_file(os.path.join(dirpath, filename))
                if relevant_file:
                    relevant_files.append(relevant_file)

    return relevant_files


def is_relevant_file(file_path: str) -> bool:
    file_name = os.path.basename(file_path).lower()

    if file_name in REQUIREMENTS_FILES:
        return True

    if file_path.endswith(PYTHON_EXTENSIONS) and not file_path.endswith(PYTHON_IGNORES):
        return is_relevant_python_file(file_path)

    if file_path.endswith(ELIXIR_EXTENSIONS):
        return is_relevant_elixir_file(file_path)

    return file_path.endswith(".py") or file_path.endswith(ELIXIR_EXTENSIONS)


def is_relevant_python_file(file_path: str) -> bool:
    content = ""
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning("Failed to read file %s: %s", file_path, e)
        return True

    return has_relevant_imports(content)


def is_relevant_elixir_file(file_path: str) -> bool:
    content = ""
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning("Failed to read file %s: %s", file_path, e)
        return True

    return has_relevant_elixir_imports(content)


def has_relevant_imports(content: str) -> bool:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _matches_framework(alias.name):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and _matches_framework(node.module):
                return True

    return False


def has_relevant_elixir_imports(content: str) -> bool:
    for pattern, _framework in ELIXIR_FRAMEWORK_PATTERNS:
        if pattern.search(content):
            return True
    return False


def _detect_framework_in_file(file_path: str) -> RelevantFile | None:
    """Read a Python file and return a RelevantFile if it imports a known framework."""
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning("Failed to read file %s: %s", file_path, e)
        return RelevantFile(path=file_path, type=FileType.PYTHON)

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                framework = _get_framework_name(alias.name)
                if framework:
                    return RelevantFile(
                        path=file_path,
                        type=FileType.PYTHON,
                        evidence=ast.get_source_segment(content, node)
                        or f"import {alias.name}",
                        framework=framework,
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                framework = _get_framework_name(node.module)
                if framework:
                    return RelevantFile(
                        path=file_path,
                        type=FileType.PYTHON,
                        evidence=ast.get_source_segment(content, node)
                        or f"from {node.module} import ...",
                        framework=framework,
                    )

    return None


def _detect_framework_in_elixir_file(file_path: str) -> RelevantFile | None:
    """Read an Elixir file and return a RelevantFile if it references a known framework or agent construct."""
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning("Failed to read file %s: %s", file_path, e)
        return RelevantFile(path=file_path, type=FileType.ELIXIR)

    for pattern, framework in ELIXIR_FRAMEWORK_PATTERNS:
        match = pattern.search(content)
        if match:
            return RelevantFile(
                path=file_path,
                type=FileType.ELIXIR,
                evidence=match.group(0),
                framework=framework,
            )

    return None


def _matches_framework(module: str) -> bool:
    return _get_framework_name(module) is not None


def _get_framework_name(module: str) -> str | None:
    for root, name in FRAMEWORK_ROOTS.items():
        if module == root or module.startswith(root + "."):
            return name
    return None

