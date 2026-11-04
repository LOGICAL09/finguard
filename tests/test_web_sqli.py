from datetime import datetime
from attack_simulator.generator import normal_web_requests, sql_injection_attack
from detection_engine.rules import run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk, severity_label    

DAY = datetime(2026, 10, 14)

def alerts_for(events):
    alerts = []
    for event in events:
        alerts.extend(run_rules(event , {}))
    return alerts

def test_sql_injection_attempts_are_flagged():
    events = sql_injection_attack(DAY.replace(hour=15, minute=20))

    alerts = alerts_for(events)

    assert len(alerts) == 3
    for alert in alerts:
        assert alert.alert_type == "SQL_INJECTION_ATTEMPT"
        

def test_sql_injection_becomes_one_medium_incident():
    events = sql_injection_attack(DAY.replace(hour=15, minute=20))

    incidents = correlate(alerts_for(events))
    score, _ = calculate_risk(incidents[0])

    assert len(incidents) == 1
    assert score == 35
    assert severity_label(score) == "MEDIUM"
    
def test_normal_web_traffic_raises_no_alert():
    # Includes a harmless apostrophe: q=men's shoes
    assert alerts_for(normal_web_requests(DAY)) == []