from datetime import datetime

from attack_simulator.generator import normal_day , account_takeover
from detection_engine.rules import build_profiles , run_rules 
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk
from risk_engine.explain import explain_incident

DAY = datetime(2026, 10, 14)

def test_explanation_mentions_the_key_facts ():
    profiles = build_profiles(normal_day(DAY))
    alerts = []
    for event in account_takeover(DAY.replace(hour= 14, minute=5)):
        alerts.extend(run_rules(event , profiles))
    
    incident = correlate(alerts)[0]
    score , breakdown = calculate_risk(incident)
    text = explain_incident(incident , score , breakdown)
    
    assert "INC-0001" in text
    assert "EMP-SUPPORT-01" in text
    assert "94/100" in text
    assert "logged in from an unusual country" in text
    assert "production resource" in text
    