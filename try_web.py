from datetime import datetime
from attack_simulator.generator import normal_web_requests, sql_injection_attack
from detection_engine.rules import run_rules
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk, severity_label
from risk_engine.explain import explain_incident

day = datetime(2026, 10, 14)
events = normal_web_requests(day) + sql_injection_attack(day.replace(hour=15, minute=20))
events.sort(key=lambda event: event.timestamp)

alerts = []
for event in events:
    alerts.extend(run_rules(event, {}))

print("web requests:", len(events), " alerts:", len(alerts))

for incident in correlate(alerts):
    score, breakdown = calculate_risk(incident)
    print(incident.incident_id, incident.user_id)
    print("risk score:", score, "/ 100 -", severity_label(score))
    for name, points, reason in breakdown:
        print("  +" + str(points), name, "-", reason)
    print()
    print(explain_incident(incident, score, breakdown))