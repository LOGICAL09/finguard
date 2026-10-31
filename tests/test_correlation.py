from datetime import datetime

from attack_simulator.generator import normal_day, account_takeover
from detection_engine.rules import build_profiles, run_rules
from correlation_engine.correlate import correlate

DAY = datetime(2026, 10, 14)

def collect_alerts(events,profiles) :
    """ run rules on a list of events and return a list of alerts """
    alerts = []
    for event in events :
        alerts.extend(run_rules(event, profiles))
    return alerts

def test_attack_becomes_one_incident():
    profiles = build_profiles(normal_day(DAY))
    attack_events = account_takeover(DAY.replace(hour= 14 , minute= 5))
    
    incidents = correlate(collect_alerts(attack_events,profiles))
    
    assert len (incidents) == 1
    assert incidents[0].user_id == "EMP-SUPPORT-01"
    assert len(incidents[0].alerts) == 6
    

def test_normal_day_creates_no_incident():
    history = normal_day(DAY)
    profiles = build_profiles(history)
    
    incidents = correlate(collect_alerts(normal_day(DAY) , profiles)) 
    
    assert incidents == []   