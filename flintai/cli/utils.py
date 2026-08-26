"""Subcommand for `flintai init`."""

import logging
import os
import stat
import uuid
from pathlib import Path

from flintai.cli.console import console, select

logger = logging.getLogger(__name__)

CLIENT_ID_ENV_VAR = "FLINTAI_CLIENT_ID"
TELEMETRY_CONSENT_ENV_VAR = "FLINTAI_TELEMETRY_CONSENT"


def get_flintai_dir() -> Path:
    return Path.home() / ".flintai"


def get_flintai_env_path() -> Path:
    """Return the ``.env`` to use, preferring a project-local one.

    If the current working directory contains a ``.env`` it takes precedence;
    otherwise fall back to the global ``~/.flintai/.env``.
    """
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        return cwd_env
    return get_flintai_dir() / ".env"


def get_flintai_config_path() -> Path:
    return get_flintai_dir() / "config.json"


_CI_ENV_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "JENKINS_URL",
    "TRAVIS",
    "BUILDKITE",
    "CODEBUILD_BUILD_ID",
    "TF_BUILD",
    "BITBUCKET_PIPELINE",
    "TEAMCITY_VERSION",
)


def is_ci() -> bool:
    return any(os.environ.get(v) for v in _CI_ENV_VARS)


def get_client_id() -> str | None:
    return os.environ.get(CLIENT_ID_ENV_VAR)


def generate_client_id() -> str:
    return str(uuid.uuid4())


def ensure_client_id() -> None:
    if os.environ.get(CLIENT_ID_ENV_VAR):
        return

    client_id = generate_client_id()
    os.environ[CLIENT_ID_ENV_VAR] = client_id

    env_path = get_flintai_env_path()
    if env_path.exists():
        with open(env_path, "a") as f:
            f.write(f"{CLIENT_ID_ENV_VAR}={client_id}\n")
        env_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return

    logger.warning("dot env file missing, client id not persisted")


def get_telemetry_consent() -> bool:
    return os.environ.get(TELEMETRY_CONSENT_ENV_VAR, "").lower() == "true"


def prompt_telemetry_consent() -> str:
    console.print(
        "[dim]Flint AI collects anonymous usage analytics to improve the product.[/dim]"
    )
    console.print(
        "[dim]No code, prompts, keys, or personal data is ever collected.[/dim]"
    )
    console.print("[dim]You can change this at any time in your .env config.[/dim]")
    console.print()
    choice = select(
        "Do you consent to sharing anonymous usage analytics?",
        options=["Y", "N"],
        default_index=0,
    )
    console.print()

    return "true" if choice.lower() == "y" else "false"


def ensure_telemetry_consent() -> None:
    if os.environ.get(TELEMETRY_CONSENT_ENV_VAR):
        return

    if is_ci():
        os.environ[TELEMETRY_CONSENT_ENV_VAR] = "false"
        return

    value = prompt_telemetry_consent()
    os.environ[TELEMETRY_CONSENT_ENV_VAR] = value

    env_path = get_flintai_env_path()
    if env_path.exists():
        with open(env_path, "a") as f:
            f.write(f"{TELEMETRY_CONSENT_ENV_VAR}={value}\n")
        env_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
