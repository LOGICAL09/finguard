from datetime import datetime
from attack_simulator.generator import normal_day
events = normal_day(datetime(2026, 10 , 14))

print ("total events :" ,  len(events))
for event in events :
    print(
        event.timestamp,
        event.event_type.value,
        event.actor.userid,
        event.source.ip,
        event.target.resource_id,
    )
    