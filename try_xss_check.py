from datetime import datetime
from attack_simulator.generator import xss_attack
from detection_engine.rules import run_rules

for event in xss_attack(datetime(2026, 10, 14, 16, 0)):
    for alert in run_rules(event, {}):
        print(alert.alert_type, "-", alert.reason)