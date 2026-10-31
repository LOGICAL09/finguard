from datetime import datetime
from attack_simulator.generator import normal_day, account_takeover
from detection_engine.rules import build_profiles , run_rules
from correlation_engine.correlate import correlate

day = datetime(2026, 10 , 14)
profiles = build_profiles(normal_day(day))
attack_events = account_takeover(day.replace(hour = 14, minute = 5))

alerts = []
for event in attack_events :
    alerts.extend(run_rules(event, profiles))
    
print("alerts : " , len(alerts))

incidents = correlate(alerts)
print("incidents : " , len(incidents))

for incident in incidents :
    print(incident.incident_id, incident.user_id)
    for alert in incident.alerts :
        print (" " , alert.event.timestamp,alert.alert_type , "-" , alert.reason) 
           