from datetime import datetime , timedelta

from attack_simulator.generator import brute_force_attack, make_event
from detection_engine.rules import detect_brute_force
from event_pipeline.schema import EventType

DAY = datetime(2026, 10, 14)

def test_many_fast_failures_raise_brute_force():
    events = brute_force_attack(DAY.replace(hour=11 , minute= 0))
    
    alerts = detect_brute_force(events)
    
    assert len(alerts) == 1
    assert alerts[0].alert_type == "BRUTE_FORCE"
    assert alerts[0].event.actor.user_id == "EMP-DEV-01"
    
def test_two_typos_do_not_raise_brute_force():
    events = brute_force_attack(DAY.replace(hour=11 , minute=0) , attempts=2)
    
    assert detect_brute_force(events) == []
    
def test_slow_failures_do_not_raise_brute_force():
    #6 failures , but one per hour : this is just a forgetful user
    events = []
    for hour in range (6):
        events.append(make_event(
            EventType.LOGIN_FAILED,
            "EMP-DEV-01",
            DAY.replace(hour=8) + timedelta(hours=hour),
        ))
    assert detect_brute_force(events) == []

