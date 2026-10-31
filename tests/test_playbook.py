from datetime import datetime

from attack_simulator.generator import normal_day, account_takeover
from detection_engine.rules import build_profiles, run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk
from incident_response.playbook import classify_incident, run_playbook

DAY = datetime(2026, 10, 14)


def incident_for(attack_events):
    profiles = build_profiles(normal_day(DAY))
    alerts = []
    for event in attack_events:
        alerts.extend(run_rules(event, profiles))
    return correlate(alerts)[0]

def test_full_attack_runs_the_playbook():
    incident = incident_for(account_takeover(DAY.replace(hour=14, minute=5)))
    score, _ = calculate_risk(incident)
    
    audit_log = run_playbook(incident, score)
    
    assert classify_incident(incident) == "ACCOUNT_TAKEOVER"
    assert len(audit_log) == 5
    for entry in audit_log:
        assert entry["status"] == "SIMULATED"


def test_weak_incident_does_not_trigger_playbook():
    #only the login event : score 25, is low
    incident = incident_for(account_takeover(DAY.replace(hour = 14, minute = 5))[:1])
    score, _= calculate_risk(incident)
    
    assert run_playbook(incident, score)  == []       
    