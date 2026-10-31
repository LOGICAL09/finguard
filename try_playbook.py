from datetime import datetime
from attack_simulator.generator import normal_day, account_takeover
from detection_engine.rules import build_profiles, run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk
from incident_response.playbook import classify_incident, run_playbook

day = datetime(2026, 10, 14)
profiles = build_profiles(normal_day(day))
attack_events = account_takeover(day.replace(hour=14, minute=5))

alerts = []
for event in attack_events:
    alerts.extend(run_rules(event, profiles))

for incident in correlate(alerts):
    score, breakdown = calculate_risk(incident)
    print(incident.incident_id, classify_incident(incident), "score", score)
    for entry in run_playbook(incident, score):
        print("  ", entry["action"], "-", entry["status"], "| approval needed:", entry["human_approval_required"])