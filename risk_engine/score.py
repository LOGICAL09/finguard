# How many points each piece of evidence adds to an incident's risk
RISK_POINTS = {
    "NEW_DEVICE_LOGIN": 10,
    "UNUSUAL_LOCATION": 15,
    "MFA_CHANGED": 20,
    "NEW_API_KEY": 15,
    "PRIVILEGE_ESCALATION": 20,
    "SENSITIVE_RESOURCE_ACCESS": 14,
    "BRUTE_FORCE": 40,
    "SQL_INJECTION_ATTEMPT": 35,
}


def calculate_risk(incident):
    """Add up the points for an incident. Return the score and the breakdown."""
    breakdown = []   # one entry per piece of evidence: (name, points, reason)
    seen = set()     # alert types we already counted
    total = 0

    for alert in incident.alerts:
        # Count each type of evidence only once per incident
        if alert.alert_type in seen:
            continue
        seen.add(alert.alert_type)

        points = RISK_POINTS.get(alert.alert_type, 0)   # unknown type adds 0
        breakdown.append((alert.alert_type, points, alert.reason))
        total += points

    score = min(total, 100)   # the score never goes above 100
    return score, breakdown


def severity_label(score):
    """Turn a score into a word the analyst understands."""
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"