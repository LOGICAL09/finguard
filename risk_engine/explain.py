from risk_engine.score import severity_label

# A plain-language phrase for each type of evidence
EVIDENCE_PHRASES = {
    "NEW_DEVICE_LOGIN": "used a new device",
    "UNUSUAL_LOCATION": "logged in from an unusual country",
    "MFA_CHANGED": "changed MFA settings",
    "NEW_API_KEY": "created a new API key",
    "PRIVILEGE_ESCALATION": "was granted admin rights",
    "SENSITIVE_RESOURCE_ACCESS": "accessed a production resource",
    "BRUTE_FORCE": "had many failed login attempts",
    "SQL_INJECTION_ATTEMPT": "sent requests that look like SQL injection",
    "XSS_ATTEMPT": "sent requests that look like cross-site scripting (XSS)",
}


def explain_incident(incident, score, breakdown):
    """Write a short, plain-language explanation of why an incident was flagged."""
    # 1) Turn each piece of evidence into a phrase
    phrases = []
    for alert_type, points, reason in breakdown:
        phrases.append(EVIDENCE_PHRASES.get(alert_type, reason))

    # 2) Join the phrases like: "a, b, c and d"
    if len(phrases) > 1:
        actions = ", ".join(phrases[:-1]) + " and " + phrases[-1]
    else:
        actions = phrases[0]

    # 3) How long did it all take?
    first_time = incident.alerts[0].event.timestamp
    last_time = incident.alerts[-1].event.timestamp
    minutes = int((last_time - first_time).total_seconds() // 60)
    time_text = f" within {minutes} minutes" if minutes > 0 else ""

    # 4) A closing sentence that fits how much evidence there is
    if len(phrases) > 1:
        closing = ("Each event alone could be harmless, but together they form a "
                   "suspicious pattern. An analyst should review this incident.")
    else:
        closing = "This single signal may be harmless, but an analyst should check it."

    # 5) Put the text together
    return (
        f"{incident.incident_id}: the account {incident.user_id} {actions}{time_text}. "
        f"Risk score: {score}/100 ({severity_label(score)}). {closing}"
    )