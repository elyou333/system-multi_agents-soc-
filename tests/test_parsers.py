import json

from ai_backend.connectors.apache_connector import parse_access_line, parse_error_line
from ai_backend.connectors.linux_auth_connector import parse_auth_line
from ai_backend.connectors.suricata_connector import parse_eve_line, parse_fast_line


def test_suricata_eve_alert():
    line = json.dumps({
        "timestamp": "2026-06-21T12:00:00.000000+0000", "event_type": "alert",
        "src_ip": "192.168.231.1", "src_port": 50100,
        "dest_ip": "192.168.231.129", "dest_port": 80, "proto": "TCP",
        "alert": {"signature": "SOC LAB - HTTP connection to Apache", "severity": 2},
    })
    event = parse_eve_line(line)
    assert event and event.source_type == "suricata_eve"
    assert event.dest_port == 80 and event.severity == "High"


def test_suricata_fast_alert():
    line = "06/21/2026-12:00:00.123456  [**] [1:1000001:1] SOC LAB - HTTP connection to Apache [**] [Classification: Misc activity] [Priority: 2] {TCP} 192.168.231.1:50100 -> 192.168.231.129:80"
    event = parse_fast_line(line)
    assert event and event.signature == "SOC LAB - HTTP connection to Apache"
    assert event.src_ip == "192.168.231.1"


def test_apache_access():
    line = '192.168.231.1 - - [21/Jun/2026:12:00:01 +0000] "GET /.env HTTP/1.1" 404 271 "-" "curl/8.0"'
    event = parse_access_line(line)
    assert event and event.event_type == "http_request"
    assert event.signature == "Web reconnaissance"


def test_ssh_failed_login():
    line = "Jun 21 12:01:00 ubuntu2404 sshd[2222]: Failed password for invalid user admin from 192.168.231.1 port 55123 ssh2"
    event = parse_auth_line(line)
    assert event and event.event_type == "ssh_failed_login"
    assert event.user == "admin" and event.dest_port == 22


def test_apache_error_fractional_timestamp():
    line = "[Sun Jun 21 12:00:04.000000 2026] [core:error] [pid 333] [client 192.168.231.1:52000] File does not exist: /var/www/html/.env"
    event = parse_error_line(line)
    assert event and event.source_type == "apache_error"
    assert event.src_ip == "192.168.231.1"
