from datetime import datetime

from attack_simulator.generator import normal_day

DAY = datetime(2026, 10, 14)


def summary(events):
    return [(e.timestamp, e.actor.user_id, e.event_type.value) for e in events]


def test_same_seed_gives_the_same_day():
    first = normal_day(DAY, seed=42)
    second = normal_day(DAY, seed=42)

    assert summary(first) == summary(second)