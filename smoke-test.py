import pytest
from main import LogEntry, FirewallAnalyzer

def test_log_entry_parsing():
    data = {"timestamp": "2026-10-08T10:00:00", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.5", "port": 443, "protocol": "TCP", "action": "ALLOW"}
    entry = LogEntry(data)
    assert entry.src_ip == "192.168.1.10"
    assert entry.action == "ALLOW"

def test_analyzer_finds_drops():
    analyzer = FirewallAnalyzer("mock_logs.json")
    analyzer.load_logs()
    suspicious = analyzer.find_suspicious_ips(threshold=2)
    assert "203.0.113.5" in suspicious
    assert "192.168.1.10" not in suspicious