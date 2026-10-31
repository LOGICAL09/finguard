from datetime import datetime
from attack_simulator.generator import normal_day, account_takeover

day = datetime(2026, 10 , 14)
events = normal_day(day) + account_takeover(day.replace(hour = 14, minute = 5))
events.sort(key = lambda event : event.timestamp)

for event in events :
    print (
        event.timestamp,
        event.event_type.value,
        event.actor.user_id,
        event.source.ip,
        event.source.device_id,
        event.source.country
    )
