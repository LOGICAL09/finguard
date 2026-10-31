from datetime import datetime
from attack_simulator.generator import brute_force_attack
from detection_engine.rules import detect_brute_force
from correlation_engine.correlate import correlate
from risk_engine.score import calculate_risk, severity_label
from risk_engine.explain import explain_incident

events = brute_force_attack(datetime(2026, 10, 14, 11, 0))
alerts = detect_brute_force(events)

for incident in correlate(alerts):
    score, breakdown = calculate_risk(incident)
    print(incident.incident_id, incident.user_id)
    print("risk score:", score, "/ 100 -", severity_label(score))
    for name, points, reason in breakdown:
        print("  +" + str(points), name, "-", reason)
    print()
    print(explain_incident(incident, score, breakdown))