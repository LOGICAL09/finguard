from datetime import datetime
from attack_simulator.generator import normal_day, account_takeover
from detection_engine.rules import build_profiles, run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk, severity_label
from risk_engine.explain import explain_incident

day = datetime(2026, 10, 14)
profiles = build_profiles(normal_day(day))
attack_events = account_takeover(day.replace(hour=14, minute=5))

alerts = []
for event in attack_events:
    alerts.extend(run_rules(event, profiles))

for incident in correlate(alerts):
    score, breakdown = calculate_risk(incident)
    print(incident.incident_id, incident.user_id)
    print("risk score:", score, "/ 100 -", severity_label(score))
    for name, points, reason in breakdown:
        print("  +" + str(points), name, "-", reason)

    print()
    print(explain_incident(incident, score, breakdown))