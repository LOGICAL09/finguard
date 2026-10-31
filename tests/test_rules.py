from datetime import datetime
from attack_simulator.generator import account_takeover, normal_day
from detection_engine.rules import build_profiles, run_rules

DAY = datetime(2026, 10 , 14)

def test_attack_is_flagged() :
    profiles = build_profiles(normal_day(DAY))
    attack_events = account_takeover(DAY.replace(hour = 14, minute = 5))

    alert_types = []
    for event in attack_events :
        for alert in run_rules(event,profiles) :
            alert_types.append(alert.alert_type)

    assert "NEW_DEVICE_LOGIN" in alert_types
    assert "UNUSUAL_LOCATION" in alert_types
    assert "PRIVILEGE_ESCALATION" in alert_types
    assert "MFA_CHANGED" in alert_types
    assert "NEW_API_KEY" in alert_types
    assert "SENSITIVE_RESOURCE_ACCESS" in alert_types  

def test_normal_day_is_not_flagged() :
    history = normal_day(DAY)
    profiles = build_profiles(history)

    alert_types = []

    for event in normal_day(DAY) :
        for alert in run_rules(event,profiles) :
            alert_types.append(alert.alert_type)

    assert alert_types == []        