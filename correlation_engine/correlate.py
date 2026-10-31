from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class Incident:
    incident_id: str
    user_id: str
    alerts: list = field(default_factory=list)


def correlate(alerts, window_minutes=10):
    """Group alerts into incidents based on user_id and time window."""
    window = timedelta(minutes=window_minutes)
    incidents = []

    # Look at the alerts in time order
    ordered_alerts = sorted(alerts, key=lambda alert: alert.event.timestamp)

    for alert in ordered_alerts:
        user_id = alert.event.actor.user_id
        alert_time = alert.event.timestamp
        placed = False

        for incident in incidents:
            last_time = incident.alerts[-1].event.timestamp
            same_user = incident.user_id == user_id
            close_in_time = alert_time - last_time <= window

            if same_user and close_in_time:
                incident.alerts.append(alert)
                placed = True
                break

        if not placed:
            number = len(incidents) + 1
            incidents.append(Incident(
                incident_id=f"INC-{number:04d}",
                user_id=user_id,
                alerts=[alert],
            ))

    return incidents