from __future__ import annotations

import html
import json
import socket
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_backend.config import get_settings
from ai_backend.adaptive import load_adaptive_profile, record_analyst_feedback
from ai_backend.database.db import connect

st.set_page_config(
    page_title="Sentinel AI · SOC Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

settings = get_settings()
connect(settings.database_path).close()

SEVERITY_COLORS = {
    "Critical": "#ff4d6d",
    "High": "#ff8c42",
    "Medium": "#f7c948",
    "Low": "#38bdf8",
}

LOG_SOURCES = [
    {
        "zone": "SIEM",
        "host": settings.elastic_url or "Export local",
        "label": "Elastic Security",
        "source_type": "siem_elastic",
        "local": settings.siem_logs_dir / "elastic_alerts.jsonl",
        "remote": settings.elastic_url or "shared_logs/siem/elastic_alerts.jsonl",
    },
    {
        "zone": "SIEM",
        "host": settings.splunk_url or "Export local",
        "label": "Splunk Enterprise",
        "source_type": "siem_splunk",
        "local": settings.siem_logs_dir / "splunk_alerts.jsonl",
        "remote": settings.splunk_url or "shared_logs/siem/splunk_alerts.jsonl",
    },
    {
        "zone": "SOC SENSOR",
        "host": settings.soc_host,
        "label": "Suricata EVE",
        "source_type": "suricata_eve",
        "local": settings.soc_logs_dir / "eve.json",
        "remote": settings.soc_suricata_eve,
    },
    {
        "zone": "SOC SENSOR",
        "host": settings.soc_host,
        "label": "Suricata Fast",
        "source_type": "suricata_fast",
        "local": settings.soc_logs_dir / "fast.log",
        "remote": settings.soc_suricata_fast,
    },
    {
        "zone": "VICTIM SERVER",
        "host": settings.victim_host,
        "label": "Apache Access",
        "source_type": "apache_access",
        "local": settings.victim_logs_dir / "apache_access.log",
        "remote": settings.victim_apache_access,
    },
    {
        "zone": "VICTIM SERVER",
        "host": settings.victim_host,
        "label": "Apache Error",
        "source_type": "apache_error",
        "local": settings.victim_logs_dir / "apache_error.log",
        "remote": settings.victim_apache_error,
    },
    {
        "zone": "VICTIM SERVER",
        "host": settings.victim_host,
        "label": "Linux Auth",
        "source_type": "linux_auth",
        "local": settings.victim_logs_dir / "auth.log",
        "remote": settings.victim_auth_log,
    },
    {
        "zone": "VICTIM SERVER",
        "host": settings.victim_host,
        "label": "Linux Syslog",
        "source_type": "linux_syslog",
        "local": settings.victim_logs_dir / "syslog",
        "remote": settings.victim_syslog,
    },
]


@st.cache_data(ttl=5)
def query(sql: str, params: tuple = ()) -> pd.DataFrame:
    with sqlite3.connect(settings.database_path) as connection:
        return pd.read_sql_query(sql, connection, params=params)


@st.cache_data(ttl=20)
def ssh_reachable(host: str) -> bool:
    try:
        with socket.create_connection((host, 22), timeout=0.35):
            return True
    except OSError:
        return False


def source_inventory() -> pd.DataFrame:
    counts = query("SELECT source_type, COUNT(*) AS records FROM raw_events GROUP BY source_type")
    count_map = dict(zip(counts["source_type"], counts["records"])) if not counts.empty else {}
    rows = []
    for source in LOG_SOURCES:
        path: Path = source["local"]
        exists = path.exists()
        rows.append(
            {
                "Zone": source["zone"],
                "Source": source["label"],
                "Hôte Linux": source["host"],
                "Copie locale": "Prête" if exists else "Absente",
                "Taille": f"{path.stat().st_size / 1024:.1f} KB" if exists else "—",
                "Dernière modification": (
                    datetime.fromtimestamp(path.stat().st_mtime).strftime("%d/%m/%Y %H:%M")
                    if exists else "—"
                ),
                "Événements SQLite": int(count_map.get(source["source_type"], 0)),
                "Chemin distant": source["remote"],
            }
        )
    return pd.DataFrame(rows)


def machine_card(title: str, role: str, host: str, nat_ip: str, services: str, accent: str) -> None:
    online = ssh_reachable(host)
    state_class = "online" if online else "offline"
    state_text = "SSH joignable" if online else "SSH non vérifié"
    st.markdown(
        f"""
        <div class="machine-card" style="--accent:{accent}">
          <div class="machine-head">
            <div>
              <div class="eyebrow">{html.escape(role)}</div>
              <div class="machine-title">{html.escape(title)}</div>
            </div>
            <span class="status {state_class}"><i></i>{state_text}</span>
          </div>
          <div class="machine-ip">{html.escape(host)}</div>
          <div class="machine-meta">Host-only · ens37</div>
          <div class="machine-row"><span>NAT · ens33</span><strong>{html.escape(nat_ip)}</strong></div>
          <div class="machine-row"><span>Services</span><strong>{html.escape(services)}</strong></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def incident_card(row: pd.Series) -> None:
    severity = str(row["severity"])
    color = SEVERITY_COLORS.get(severity, "#94a3b8")
    st.markdown(
        f"""
        <div class="incident-card" style="--sev:{color}">
          <div class="incident-top">
            <span class="severity-pill">{html.escape(severity)}</span>
            <span class="incident-id">{html.escape(str(row["incident_uid"]))}</span>
          </div>
          <div class="incident-title">{html.escape(str(row["title"]))}</div>
          <div class="incident-grid">
            <span>SOURCE<strong>{html.escape(str(row["src_ip"] or "Inconnue"))}</strong></span>
            <span>DESTINATION<strong>{html.escape(str(row["dest_ip"] or "Inconnue"))}</strong></span>
            <span>CONFIANCE<strong>{float(row["confidence"]):.0%}</strong></span>
            <span>STATUT<strong>{html.escape(str(row["status"]))}</strong></span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.markdown(
    """
    <style>
      :root {
        --bg: #07111f;
        --panel: #0d1b2d;
        --panel-2: #10233a;
        --line: rgba(148, 163, 184, .17);
        --text: #e7eef8;
        --muted: #8ca0b8;
        --cyan: #25d0e8;
        --green: #35e0a1;
      }
      .stApp {
        background:
          radial-gradient(circle at 78% -10%, rgba(37,208,232,.12), transparent 30rem),
          linear-gradient(180deg, #07111f 0%, #081522 100%);
        color: var(--text);
      }
      [data-testid="stSidebar"] {
        background: #081422;
        border-right: 1px solid var(--line);
      }
      [data-testid="stHeader"] { background: transparent; }
      .block-container { max-width: 1500px; padding-top: 2rem; padding-bottom: 4rem; }
      h1, h2, h3 { color: #f5f9ff !important; letter-spacing: -.02em; }
      p, label, [data-testid="stCaptionContainer"] { color: var(--muted); }
      .brand {
        display:flex; align-items:center; justify-content:space-between;
        border-bottom:1px solid var(--line); padding-bottom:1.4rem; margin-bottom:1.4rem;
      }
      .brand-title { font-size:1.9rem; font-weight:800; color:#f7fbff; letter-spacing:-.04em; }
      .brand-title b { color:var(--cyan); }
      .brand-sub { color:var(--muted); font-size:.8rem; letter-spacing:.17em; margin-top:.2rem; }
      .mode-pill {
        padding:.45rem .75rem; border:1px solid rgba(37,208,232,.35); border-radius:99px;
        color:var(--cyan); background:rgba(37,208,232,.08); font-size:.72rem; font-weight:800;
      }
      .section-label {
        color:#7890aa; font-size:.7rem; letter-spacing:.18em; font-weight:800;
        margin:1.5rem 0 .65rem;
      }
      .machine-card {
        background:linear-gradient(145deg, rgba(16,35,58,.96), rgba(10,25,42,.96));
        border:1px solid var(--line); border-top:2px solid var(--accent); border-radius:14px;
        padding:1.25rem; min-height:230px; box-shadow:0 16px 35px rgba(0,0,0,.16);
      }
      .machine-head { display:flex; justify-content:space-between; gap:1rem; align-items:flex-start; }
      .eyebrow { color:var(--accent); font-size:.66rem; font-weight:900; letter-spacing:.18em; }
      .machine-title { color:#eef6ff; font-size:1.15rem; font-weight:750; margin-top:.25rem; }
      .machine-ip {
        font-family:ui-monospace, SFMono-Regular, Consolas, monospace; color:#fff;
        font-size:1.4rem; margin:1.3rem 0 .15rem;
      }
      .machine-meta { color:#698097; font-size:.74rem; margin-bottom:1.1rem; }
      .machine-row {
        border-top:1px solid var(--line); display:flex; justify-content:space-between;
        padding:.62rem 0; color:#7f93aa; font-size:.78rem;
      }
      .machine-row strong { color:#cbd8e7; font-weight:600; }
      .status { font-size:.65rem; color:#8295aa; white-space:nowrap; }
      .status i { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:.4rem; }
      .status.online i { background:var(--green); box-shadow:0 0 10px var(--green); }
      .status.offline i { background:#64748b; }
      .pipeline {
        display:grid; grid-template-columns:repeat(6,1fr); align-items:center;
        background:rgba(13,27,45,.74); border:1px solid var(--line); border-radius:14px;
        overflow:hidden; margin:.5rem 0 1.5rem;
      }
      .pipe-step { padding:1.05rem .7rem; text-align:center; position:relative; }
      .pipe-step:not(:last-child):after {
        content:"›"; color:#3c5874; position:absolute; right:-.2rem; font-size:1.5rem; top:.6rem;
      }
      .pipe-step b { display:block; color:#dce8f5; font-size:.78rem; }
      .pipe-step span { color:#607991; font-size:.62rem; letter-spacing:.06em; }
      [data-testid="stMetric"] {
        background:linear-gradient(145deg, rgba(16,35,58,.92), rgba(11,27,45,.9));
        border:1px solid var(--line); border-radius:12px; padding:1rem 1.1rem;
      }
      [data-testid="stMetricLabel"] { color:#7890aa; text-transform:uppercase; letter-spacing:.08em; }
      [data-testid="stMetricValue"] { color:#f4f9ff; }
      .incident-card {
        background:rgba(13,27,45,.84); border:1px solid var(--line);
        border-left:3px solid var(--sev); border-radius:11px; padding:1rem 1.1rem; margin:.65rem 0;
      }
      .incident-top { display:flex; justify-content:space-between; }
      .severity-pill { color:var(--sev); font-weight:800; font-size:.69rem; letter-spacing:.08em; }
      .incident-id { color:#597188; font-family:monospace; font-size:.68rem; }
      .incident-title { color:#e8f1fb; font-size:1rem; font-weight:700; margin:.55rem 0 .8rem; }
      .incident-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:.7rem; }
      .incident-grid span { color:#607991; font-size:.61rem; letter-spacing:.08em; }
      .incident-grid strong { display:block; color:#b9c9d9; font-size:.76rem; margin-top:.2rem; }
      [data-baseweb="tab-list"] { gap:.4rem; border-bottom:1px solid var(--line); }
      [data-baseweb="tab"] { color:#7890aa; background:transparent; }
      [aria-selected="true"] { color:var(--cyan) !important; }
      [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:10px; overflow:hidden; }
      .safe-note {
        border:1px solid rgba(53,224,161,.22); background:rgba(53,224,161,.06);
        color:#91bcae; border-radius:9px; padding:.8rem; font-size:.75rem;
      }
      @media (max-width: 900px) {
        .pipeline { grid-template-columns:repeat(2,1fr); }
        .incident-grid { grid-template-columns:repeat(2,1fr); }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


with st.sidebar:
    st.markdown(
        """
        <div style="font-weight:850;font-size:1.12rem;color:#f3f8ff">SENTINEL <span style="color:#25d0e8">AI</span></div>
        <div style="color:#607991;font-size:.68rem;letter-spacing:.16em;margin-bottom:1.4rem">SOC CONTROL PLANE</div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown('<div class="section-label">OPÉRATIONS</div>', unsafe_allow_html=True)
    requested_mode = st.radio(
        "Mode de collecte",
        options=["local", "ssh"],
        index=0 if settings.log_mode == "local" else 1,
        format_func=lambda mode: "Fichiers locaux" if mode == "local" else "Collecte SSH",
        help="Le mode SSH copie les journaux des deux VM avant analyse.",
    )
    run_limit = st.number_input("Limite de lignes", min_value=10, max_value=100000, value=500, step=100)
    if st.button("▶  Collecter et analyser", type="primary", width="stretch"):
        try:
            from ai_backend.main import run

            with st.spinner("Pipeline multi-agents en cours…"):
                result = run(requested_mode, int(run_limit))
            st.cache_data.clear()
            st.success(
                f"{len(result.get('incidents', []))} incident(s) · "
                f"{len(result.get('normalized_events', []))} événement(s)"
            )
        except Exception as exc:
            st.error(f"Échec du pipeline : {exc}")
    if st.button("↻  Actualiser les données", width="stretch"):
        st.cache_data.clear()
        st.rerun()

    st.markdown('<div class="section-label">LABORATOIRE</div>', unsafe_allow_html=True)
    st.caption(f"SOC · {settings.soc_host}")
    st.caption(f"Victime · {settings.victim_host}")
    st.caption(f"Ollama · {settings.ollama_model}")
    st.markdown(
        '<div class="safe-note">MODE SÛR<br>Toutes les réponses sont simulées et auditables.</div>',
        unsafe_allow_html=True,
    )


latest_run = query("SELECT * FROM runs ORDER BY id DESC LIMIT 1")
incidents = query("SELECT * FROM incidents ORDER BY id DESC")
raw_count = int(query("SELECT COUNT(*) AS n FROM raw_events").iloc[0]["n"])
action_count = int(query("SELECT COUNT(*) AS n FROM actions").iloc[0]["n"])
critical_count = int(
    query("SELECT COUNT(*) AS n FROM incidents WHERE severity IN ('High','Critical')").iloc[0]["n"]
)

run_status = latest_run.iloc[0]["status"] if not latest_run.empty else "Aucune exécution"
st.markdown(
    f"""
    <div class="brand">
      <div>
        <div class="brand-title">SOC <b>Operations</b> Center</div>
        <div class="brand-sub">MULTI-AGENT THREAT DETECTION · LOCAL AI</div>
      </div>
      <span class="mode-pill">{html.escape(requested_mode.upper())} · {html.escape(run_status)}</span>
    </div>
    """,
    unsafe_allow_html=True,
)

overview_tab, infra_tab, alerts_tab, analysis_tab, reports_tab, audit_tab = st.tabs(
    ["Vue générale", "Infrastructure Linux", "Événements", "Incidents IA", "Rapports", "Audit"]
)

with overview_tab:
    st.markdown('<div class="section-label">ÉTAT DU LABORATOIRE</div>', unsafe_allow_html=True)
    vm1, vm2 = st.columns(2)
    with vm1:
        machine_card(
            "ubuntu2404 · SOC",
            "CAPTEUR RÉSEAU",
            settings.soc_host,
            "192.168.10.132",
            "Suricata · SSH",
            "#25d0e8",
        )
    with vm2:
        machine_card(
            "ubuntu2404 · Victime",
            "SERVEUR SURVEILLÉ",
            settings.victim_host,
            "192.168.10.133",
            "Apache · SSH · Syslog",
            "#8b7cf6",
        )

    st.markdown('<div class="section-label">PIPELINE AGENTIQUE</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="pipeline">
          <div class="pipe-step"><b>Logs + SIEM</b><span>ELASTIC · SPLUNK</span></div>
          <div class="pipe-step"><b>Extracteur</b><span>NORMALISATION</span></div>
          <div class="pipe-step"><b>Analyseur</b><span>CORRÉLATION</span></div>
          <div class="pipe-step"><b>Ollama</b><span>PHI3 LOCAL</span></div>
          <div class="pipe-step"><b>Rapporteur</b><span>MARKDOWN FR</span></div>
          <div class="pipe-step"><b>Réponse</b><span>SIMULATION</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Événements", f"{raw_count:,}".replace(",", " "))
    k2.metric("Incidents", len(incidents))
    k3.metric("Priorité haute", critical_count)
    k4.metric("Actions simulées", action_count)

    left, right = st.columns([1.05, 1.6])
    with left:
        st.markdown('<div class="section-label">RÉPARTITION PAR SÉVÉRITÉ</div>', unsafe_allow_html=True)
        severity = query(
            "SELECT severity, COUNT(*) AS incidents FROM incidents GROUP BY severity"
        )
        if severity.empty:
            st.info("Aucun incident. Lancez une analyse depuis le panneau gauche.")
        else:
            severity["color"] = severity["severity"].map(SEVERITY_COLORS)
            chart = (
                alt.Chart(severity)
                .mark_bar(cornerRadiusEnd=5, height=22)
                .encode(
                    x=alt.X("incidents:Q", title=None, axis=alt.Axis(grid=False, labels=False, ticks=False)),
                    y=alt.Y("severity:N", title=None, sort=["Critical", "High", "Medium", "Low"]),
                    color=alt.Color("severity:N", scale=alt.Scale(
                        domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values())
                    ), legend=None),
                    tooltip=["severity", "incidents"],
                )
                .properties(height=180)
                .configure_view(strokeOpacity=0)
                .configure_axis(labelColor="#8ca0b8", domain=False)
            )
            st.altair_chart(chart, width="stretch")
    with right:
        st.markdown('<div class="section-label">INCIDENTS RÉCENTS</div>', unsafe_allow_html=True)
        if incidents.empty:
            st.info("La base ne contient pas encore d'incident.")
        else:
            for _, row in incidents.head(3).iterrows():
                incident_card(row)

with infra_tab:
    st.subheader("Infrastructure Linux et sources de télémétrie")
    st.caption(
        "Cette vue représente vos deux VM. Le dashboard tourne sur Windows; "
        "les données Linux arrivent par copie locale ou par SSH."
    )
    inventory = source_inventory()
    st.dataframe(
        inventory,
        width="stretch",
        hide_index=True,
        column_config={
            "Événements SQLite": st.column_config.ProgressColumn(
                "Événements SQLite",
                min_value=0,
                max_value=max(1, int(inventory["Événements SQLite"].max())),
            )
        },
    )
    missing = inventory[inventory["Copie locale"] == "Absente"]
    if not missing.empty:
        st.warning(
            "Copies locales manquantes : " + ", ".join(missing["Source"].tolist())
        )
    if requested_mode == "local":
        st.info(
            "LOG_MODE=local : les VM ne sont pas interrogées. Copiez leurs logs dans shared_logs "
            "ou sélectionnez Collecte SSH dans le panneau gauche."
        )

with alerts_tab:
    st.subheader("Événements normalisés")
    f1, f2, f3, f4 = st.columns(4)
    sources = query("SELECT DISTINCT source_type FROM raw_events ORDER BY source_type")
    source_values = sources["source_type"].dropna().tolist()
    source = f1.selectbox("Source", ["Toutes"] + source_values)
    severity_filter = f2.selectbox("Sévérité", ["Toutes", "Critical", "High", "Medium", "Low"])
    ip_filter = f3.text_input("Adresse IP", placeholder="192.168.231…")
    event_filter = f4.text_input("Type", placeholder="alert, http_request…")
    sql, params = "SELECT timestamp,source_type,event_type,severity,src_ip,dest_ip,signature,message FROM raw_events WHERE 1=1", []
    if source != "Toutes":
        sql += " AND source_type=?"
        params.append(source)
    if severity_filter != "Toutes":
        sql += " AND severity=?"
        params.append(severity_filter)
    if ip_filter:
        sql += " AND (src_ip LIKE ? OR dest_ip LIKE ?)"
        params.extend([f"%{ip_filter}%"] * 2)
    if event_filter:
        sql += " AND event_type LIKE ?"
        params.append(f"%{event_filter}%")
    events = query(sql + " ORDER BY id DESC LIMIT 1000", tuple(params))
    st.dataframe(events, width="stretch", hide_index=True)

with analysis_tab:
    st.subheader("Analyse et corrélation des incidents")
    if incidents.empty:
        st.info("Aucun incident disponible.")
    else:
        ids = incidents["incident_uid"].tolist()
        selected = st.selectbox("Incident", ids)
        row = incidents[incidents["incident_uid"] == selected].iloc[0]
        incident_card(row)
        a1, a2 = st.columns(2)
        with a1:
            st.markdown("#### Analyse SOC")
            st.write(row["explanation"])
        with a2:
            st.markdown("#### Recommandation")
            st.info(row["recommendation"])
        st.markdown("#### Mapping MITRE ATT&CK")
        st.code(f'{row["mitre_tactic"]} · {row["mitre_technique"]}')
        st.markdown("#### Validation analyste et apprentissage adaptatif")
        verdict_label = st.radio(
            "Verdict",
            ["Vrai positif", "Faux positif", "À revoir"],
            horizontal=True,
            key=f"verdict_{selected}",
        )
        feedback_notes = st.text_input("Note analyste", key=f"notes_{selected}")
        if st.button("Enregistrer le feedback", key=f"feedback_{selected}"):
            verdict = {
                "Vrai positif": "true_positive",
                "Faux positif": "false_positive",
                "À revoir": "needs_review",
            }[verdict_label]
            record_analyst_feedback(settings.database_path, selected, verdict, feedback_notes)
            st.cache_data.clear()
            st.success("Feedback enregistré. Les seuils restent bornés entre 3 et 10 événements.")

with reports_tab:
    st.subheader("Rapports d'incident")
    reports = sorted(
        settings.reports_dir.glob("*.md"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if reports:
        selected_report = st.selectbox("Rapport", reports, format_func=lambda path: path.name)
        st.download_button(
            "Télécharger le rapport",
            data=selected_report.read_bytes(),
            file_name=selected_report.name,
            mime="text/markdown",
        )
        st.markdown(selected_report.read_text(encoding="utf-8"))
    else:
        st.info("Aucun rapport généré.")

with audit_tab:
    sub1, sub2, sub3, sub4 = st.tabs(["Exécutions", "Actions simulées", "Artefacts locaux", "Apprentissage"])
    with sub1:
        runs = query("SELECT * FROM runs ORDER BY id DESC")
        st.dataframe(runs, width="stretch", hide_index=True)
        if not runs.empty:
            for _, row in runs.iterrows():
                errors = json.loads(row["errors"] or "[]")
                if errors:
                    with st.expander(f'{row["run_uid"]} · {len(errors)} avertissement(s)'):
                        st.code("\n".join(errors))
    with sub2:
        actions = query("SELECT * FROM actions ORDER BY id DESC")
        st.dataframe(actions, width="stretch", hide_index=True)
    with sub3:
        blocklist = settings.audit_dir / "blocklist.txt"
        notifications = settings.audit_dir / "notifications.log"
        quarantine = settings.audit_dir / "quarantine_plan.jsonl"
        remediation = settings.audit_dir / "remediation.log"
        c1, c2 = st.columns(2)
        c1.text_area(
            "Blocklist simulée",
            blocklist.read_text(encoding="utf-8") if blocklist.exists() else "",
            height=260,
        )
        c2.text_area(
            "Notifications simulées",
            notifications.read_text(encoding="utf-8") if notifications.exists() else "",
            height=260,
        )
        c3, c4 = st.columns(2)
        c3.text_area(
            "Plans d'isolation simulés",
            quarantine.read_text(encoding="utf-8") if quarantine.exists() else "",
            height=260,
        )
        c4.text_area(
            "Playbooks de remédiation",
            remediation.read_text(encoding="utf-8") if remediation.exists() else "",
            height=260,
        )
    with sub4:
        st.caption("Les seuils ne changent qu'après trois validations et restent bornés entre 3 et 10.")
        profile = load_adaptive_profile(settings.database_path)
        st.json(profile)
        feedback = query("SELECT incident_uid,incident_type,verdict,notes,created_at FROM analyst_feedback ORDER BY id DESC")
        st.dataframe(feedback, width="stretch", hide_index=True)
