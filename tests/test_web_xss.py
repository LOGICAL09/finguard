from datetime import datetime

from attack_simulator.generator import xss_attack, web_request
from detection_engine.rules import run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk, severity_label

DAY = datetime(2026, 10, 14)


def alerts_for(events):
    alerts = []
    for event in events:
        alerts.extend(run_rules(event, {}))
    return alerts


def test_xss_attempts_are_flagged():
    alerts = alerts_for(xss_attack(DAY.replace(hour=16, minute=0)))

    assert len(alerts) == 3
    for alert in alerts:
        assert alert.alert_type == "XSS_ATTEMPT"


def test_harmless_less_than_sign_is_not_xss():
    # "q=size < 10" has a "<" sign, but it is a normal search
    harmless = web_request(DAY.replace(hour=16), "198.51.100.26", "/search", "q=size+%3C+10")

    assert alerts_for([harmless]) == []


def test_xss_becomes_one_medium_incident():
    alerts = alerts_for(xss_attack(DAY.replace(hour=16, minute=0)))

    incidents = correlate(alerts)
    score, _ = calculate_risk(incidents[0])

    assert len(incidents) == 1
    assert score == 35
    assert severity_label(score) == "MEDIUM"