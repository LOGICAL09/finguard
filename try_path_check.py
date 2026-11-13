from datetime import datetime
from attack_simulator.generator import path_traversal_attack
from detection_engine.rules import run_rules

for event in path_traversal_attack(datetime(2026, 10, 14, 16, 30)):
    for alert in run_rules(event, {}):
        print(alert.alert_type, "-", alert.reason)