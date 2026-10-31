from datetime import datetime

from attack_simulator.generator import normal_day, account_takeover
from detection_engine.rules import build_profiles, run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk, severity_label
from risk_engine.explain import explain_incident

DAY = datetime(2026, 10, 14)


def incident_for(attack_events):
    """Run attack events through rules and correlation."""
    profiles = build_profiles(normal_day(DAY))
    alerts = []
    for event in attack_events:
        alerts.extend(run_rules(event, profiles))
    return correlate(alerts)


def test_full_attack_is_critical():
    attack_events = account_takeover(DAY.replace(hour=14, minute=5))
    incident = incident_for(attack_events)[0]

    score, breakdown = calculate_risk(incident)

    assert score == 94
    assert severity_label(score) == "CRITICAL"
    assert len(breakdown) == 6


def test_one_weak_signal_is_low():
    # Only the login event: a new device and a new country
    attack_events = account_takeover(DAY.replace(hour=14, minute=5))[:1]
    incident = incident_for(attack_events)[0]

    score, _ = calculate_risk(incident)

    assert score == 25
    assert severity_label(score) == "LOW"