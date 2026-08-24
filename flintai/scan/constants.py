"""constants.py — Shared constants for the agent scanner."""

ELIXIR_FILE_EXTENSIONS = (".ex", ".exs")
ELIXIR_MANIFEST_NAMES = ("mix.exs", "mix.lock")

REQUIREMENT_FILE_NAMES = (
    "requirements.txt",
    "requirements_lock.txt",
    "pyproject.toml",
    "mix.exs",
    "mix.lock",
)

PYTHON_FILE_EXTENSION = ".py"
SOURCE_FILE_EXTENSIONS = (PYTHON_FILE_EXTENSION, *ELIXIR_FILE_EXTENSIONS)

CONFIG_FILE_EXTENSIONS = (".toml", ".cfg")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

