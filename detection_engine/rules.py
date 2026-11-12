from datetime import timedelta
from dataclasses import dataclass
from event_pipeline.schema import Event, EventType
from urllib.parse import unquote_plus

# Text patterns that often appear in SQL injection attempts
SQLI_PATTERNS = ["' or ", " or 1=1", "union select", "; drop ", "sleep("]
XSS_PATTERNS = ["<script", "onerror=", "onload=", "javascript:"]


@dataclass
class Alert:
    alert_type: str   # the name of the rule that fired
    event: Event      # the event that triggered it
    reason: str       # a plain-language explanation


def build_profiles(history):
    """Learn what is normal for each user, using clean history only."""
    profiles = {}
    for event in history:
        if event.event_type == EventType.LOGIN:
            user_id = event.actor.user_id
            if user_id not in profiles:
                profiles[user_id] = {"devices": set(), "countries": set()}
            profiles[user_id]["devices"].add(event.source.device_id)
            profiles[user_id]["countries"].add(event.source.country)
    return profiles


def run_rules(event, profiles):
    """Check ONE event against all rules and return a list of alerts."""
    alerts = []
    
    # Safely fetch profile if profiles dictionary is provided
    profile = profiles.get(event.actor.user_id) if profiles and event.actor else None

    # Rules about logins (we need the user's normal profile)
    if event.event_type == EventType.LOGIN and profile is not None:
        if event.source.device_id not in profile["devices"]:
            alerts.append(Alert(
                "NEW_DEVICE_LOGIN",
                event,
                "Login from a new device not seen before for this user",
            ))
        if event.source.country not in profile["countries"]:
            alerts.append(Alert(
                "UNUSUAL_LOCATION",
                event,
                "Login from a new country not seen before for this user",
            ))

    # Rule about role changes
    if event.event_type == EventType.ROLE_CHANGED:
        if event.metadata.get("new_role") == "admin":
            alerts.append(Alert(
                "PRIVILEGE_ESCALATION",
                event,
                "Role was upgraded to admin",
            ))

    # Rule: MFA settings were changed
    if event.event_type == EventType.MFA_CHANGED:
        alerts.append(Alert(
            "MFA_CHANGED",
            event,
            "MFA settings were changed",
        ))

    # Rule: a new API key was created
    if event.event_type == EventType.API_KEY_CREATED:
        alerts.append(Alert(
            "NEW_API_KEY",
            event,
            "A new API key was created",
        ))

    # Rule: a production resource was opened
    if event.event_type == EventType.RESOURCE_ACCESS:
        if event.target and event.target.resource_id.startswith("prod"):
            alerts.append(Alert(
                "SENSITIVE_RESOURCE_ACCESS",
                event,
                "A production resource was accessed",
            ))

       # Rule: a web request that looks like a web attack
    if event.event_type == EventType.WEB_REQUEST:
        raw_query = event.metadata.get("q") or event.metadata.get("query", "")
        query = unquote_plus(raw_query).lower()

        for pattern in SQLI_PATTERNS:
            if pattern in query:
                alerts.append(Alert(
                    "SQL_INJECTION_ATTEMPT",
                    event,
                    f"web request to {event.target.resource_id} contains an SQL injection pattern",
                ))
                break

        for pattern in XSS_PATTERNS:
            if pattern in query:
                alerts.append(Alert(
                    "XSS_ATTEMPT",
                    event,
                    f"web request to {event.target.resource_id} contains an XSS pattern",
                ))
                break

    return alerts

def detect_brute_force(events, window_minutes=5, threshold=5):
    """Find users with many failed logins in short time."""
    window = timedelta(minutes=window_minutes)
    alerts = []
    
    # Collect the failed logins of each user
    failed_by_user = {}
    for event in events:
        if event.event_type == EventType.LOGIN_FAILED:
            user_id = event.actor.user_id
            if user_id not in failed_by_user:
                failed_by_user[user_id] = []
            failed_by_user[user_id].append(event)

    # Look for `threshold` failures inside one time window
    for user_id, failed_events in failed_by_user.items():
        failed_events.sort(key=lambda ev: ev.timestamp)

        for i in range(len(failed_events) - threshold + 1):
            first = failed_events[i]
            last = failed_events[i + threshold - 1]
            if last.timestamp - first.timestamp <= window:
                alerts.append(Alert(
                    "BRUTE_FORCE",
                    last,
                    f"{threshold} or more failed logins within {window_minutes} minutes",
                ))
                break   # one alert per user is enough

    return alerts
