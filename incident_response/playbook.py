# the response steps for each type of incident
# Each step: (action name , description , does a human need to approve it?)

PLAYBOOKS = {
    "ACCOUNT_TAKEOVER": [
        ("REVOKE_API_KEY", "Revoke the suspicious API key", True),
        ("FORCE_LOGOUT", "Force logout of all active sessions", True),
        ("REVERT_ROLE", "Revert the role to the previous level", True),
        ("NOTIFY_SECURITY", "Notify the security team", False),
        ("FLAG_FOR_REVIEW", "Flag the account for manual review", False),
    ],
}

def classify_incident(incident):
    """Decide what type of incident this is, from its evidence."""
    types = set()
    for alert in incident.alerts:
        types.add(alert.alert_type)

    login_anomaly = "NEW_DEVICE_LOGIN" in types or "UNUSUAL_LOCATION" in types
    if login_anomaly and "PRIVILEGE_ESCALATION" in types:
        return "ACCOUNT_TAKEOVER"
    return "SUSPICIOUS_ACTIVITY"
    

def run_playbook(incident , score):
    """simulate the response steps and return them as an audit log"""
    audit_log = []
    
    #only HIGH (61+) and CRITCAL incidents trigger a response
    if score < 61:
        return audit_log
    
    incident_type = classify_incident(incident)
    steps = PLAYBOOKS.get(incident_type , [])
    action_time = incident.alerts[-1].event.timestamp
    
    for action , description , needs_approval in steps :
        audit_log.append({
            "incident_id": incident.incident_id,
            "action": action,
            "description": description,
            "status": "SIMULATED",
            "timestamp": action_time,
            "human_approval_required": needs_approval,
        })
        
    return audit_log