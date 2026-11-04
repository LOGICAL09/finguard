from datetime import datetime
from attack_simulator.generator import normal_web_requests, sql_injection_attack

day = datetime(2026, 10, 14)
events = normal_web_requests(day) + sql_injection_attack(day.replace(hour=15, minute=20))

for event in events:
    print(event.timestamp, event.actor.user_id, event.target.resource_id, event.metadata["query"])