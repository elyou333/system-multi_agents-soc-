from __future__ import annotations

import logging
from pathlib import Path

from ai_backend.config import Settings

LOGGER = logging.getLogger(__name__)


def _collect_host(host: str, user: str, files: dict[str, Path], settings: Settings) -> None:
    import paramiko

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    kwargs = {
        "hostname": host,
        "username": user,
        "timeout": settings.ssh_timeout,
        "allow_agent": True,
        "look_for_keys": True,
    }
    if settings.ssh_password:
        kwargs["password"] = settings.ssh_password
    if settings.ssh_key_path:
        kwargs["key_filename"] = settings.ssh_key_path
    client.connect(**kwargs)
    try:
        sftp = client.open_sftp()
        try:
            for remote, local in files.items():
                local.parent.mkdir(parents=True, exist_ok=True)
                try:
                    sftp.get(remote, str(local))
                except OSError as exc:
                    raise OSError(f"{host}:{remote}: {exc}") from exc
        finally:
            sftp.close()
    finally:
        client.close()


def collect_logs_over_ssh(settings: Settings) -> tuple[bool, list[str]]:
    errors: list[str] = []
    try:
        _collect_host(settings.soc_host, settings.soc_user, {
            settings.soc_suricata_eve: settings.soc_logs_dir / "eve.json",
            settings.soc_suricata_fast: settings.soc_logs_dir / "fast.log",
        }, settings)
        _collect_host(settings.victim_host, settings.victim_user, {
            settings.victim_apache_access: settings.victim_logs_dir / "apache_access.log",
            settings.victim_apache_error: settings.victim_logs_dir / "apache_error.log",
            settings.victim_auth_log: settings.victim_logs_dir / "auth.log",
            settings.victim_syslog: settings.victim_logs_dir / "syslog",
        }, settings)
        return True, errors
    except Exception as exc:
        message = f"Collecte SSH indisponible ({exc}); repli sur les journaux locaux."
        LOGGER.warning(message)
        errors.append(message)
        return False, errors
