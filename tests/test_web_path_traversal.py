from datetime import datetime

from attack_simulator.generator import path_traversal_attack, web_request
from detection_engine.rules import run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk, severity_label

DAY = datetime(2026, 10, 14)


def alerts_for(events):
    alerts = []
    for event in events:
        alerts.extend(run_rules(event, {}))
    return alerts


def test_path_traversal_attempts_are_flagged():
    alerts = alerts_for(path_traversal_attack(DAY.replace(hour=16, minute=30)))

    assert len(alerts) == 3
    for alert in alerts:
        assert alert.alert_type == "PATH_TRAVERSAL_ATTEMPT"


def test_normal_download_is_not_flagged():
    # A normal visitor downloads a normal file
    normal = web_request(DAY.replace(hour=16), "198.51.100.27", "/download", "file=invoice.pdf")

    assert alerts_for([normal]) == []


def test_path_traversal_becomes_one_medium_incident():
    alerts = alerts_for(path_traversal_attack(DAY.replace(hour=16, minute=30)))

    incidents = correlate(alerts)
    score, _ = calculate_risk(incidents[0])

    assert len(incidents) == 1
    assert score == 35
    assert severity_label(score) == "MEDIUM"