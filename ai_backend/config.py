from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    project_root: Path
    log_mode: str
    ollama_model: str
    ollama_enabled: bool
    correlation_window_minutes: int
    ssh_timeout: int
    soc_host: str
    soc_user: str
    victim_host: str
    victim_user: str
    ssh_password: str | None
    ssh_key_path: str | None
    soc_suricata_eve: str
    soc_suricata_fast: str
    victim_apache_access: str
    victim_apache_error: str
    victim_auth_log: str
    victim_syslog: str
    siem_enabled: bool
    elastic_url: str | None
    elastic_index: str
    elastic_api_key: str | None
    splunk_url: str | None
    splunk_token: str | None
    splunk_search: str
    siem_verify_ssl: bool

    @property
    def database_path(self) -> Path:
        return self.project_root / "soc_ai.db"

    @property
    def reports_dir(self) -> Path:
        return self.project_root / "reports"

    @property
    def audit_dir(self) -> Path:
        return self.project_root / "audit"

    @property
    def soc_logs_dir(self) -> Path:
        return self.project_root / "shared_logs" / "soc"

    @property
    def victim_logs_dir(self) -> Path:
        return self.project_root / "shared_logs" / "victim"

    @property
    def siem_logs_dir(self) -> Path:
        return self.project_root / "shared_logs" / "siem"

    def ensure_directories(self) -> None:
        for path in (self.reports_dir, self.audit_dir, self.soc_logs_dir, self.victim_logs_dir, self.siem_logs_dir):
            path.mkdir(parents=True, exist_ok=True)


def get_settings(mode: str | None = None) -> Settings:
    load_dotenv()
    default_root = Path(__file__).resolve().parents[1]
    root_value = os.getenv("PROJECT_ROOT", "").strip()
    project_root = Path(root_value).expanduser() if root_value else default_root
    settings = Settings(
        project_root=project_root.resolve(),
        log_mode=(mode or os.getenv("LOG_MODE", "local")).lower(),
        ollama_model=os.getenv("OLLAMA_MODEL", "phi3"),
        ollama_enabled=os.getenv("OLLAMA_ENABLED", "true").lower() in {"1", "true", "yes"},
        correlation_window_minutes=int(os.getenv("CORRELATION_WINDOW_MINUTES", "10")),
        ssh_timeout=int(os.getenv("SSH_TIMEOUT", "10")),
        soc_host=os.getenv("SOC_HOST", "192.168.231.128"),
        soc_user=os.getenv("SOC_USER", "ubuntu"),
        victim_host=os.getenv("VICTIM_HOST", "192.168.231.129"),
        victim_user=os.getenv("VICTIM_USER", "ubuntu"),
        ssh_password=os.getenv("SSH_PASSWORD") or None,
        ssh_key_path=os.getenv("SSH_KEY_PATH") or None,
        soc_suricata_eve=os.getenv("SOC_SURICATA_EVE", "/var/log/suricata/eve.json"),
        soc_suricata_fast=os.getenv("SOC_SURICATA_FAST", "/var/log/suricata/fast.log"),
        victim_apache_access=os.getenv("VICTIM_APACHE_ACCESS", "/var/log/apache2/access.log"),
        victim_apache_error=os.getenv("VICTIM_APACHE_ERROR", "/var/log/apache2/error.log"),
        victim_auth_log=os.getenv("VICTIM_AUTH_LOG", "/var/log/auth.log"),
        victim_syslog=os.getenv("VICTIM_SYSLOG", "/var/log/syslog"),
        siem_enabled=os.getenv("SIEM_ENABLED", "true").lower() in {"1", "true", "yes"},
        elastic_url=os.getenv("ELASTIC_URL") or None,
        elastic_index=os.getenv("ELASTIC_INDEX", "logs-*,alerts-*") or "logs-*,alerts-*",
        elastic_api_key=os.getenv("ELASTIC_API_KEY") or None,
        splunk_url=os.getenv("SPLUNK_URL") or None,
        splunk_token=os.getenv("SPLUNK_TOKEN") or None,
        splunk_search=os.getenv("SPLUNK_SEARCH", "search index=* (tag=attack OR sourcetype=suricata)") or "search index=*",
        siem_verify_ssl=os.getenv("SIEM_VERIFY_SSL", "true").lower() in {"1", "true", "yes"},
    )
    settings.ensure_directories()
    return settings
