import random
from datetime import datetime, timedelta
from event_pipeline.schema import Event, EventType, Actor, Source, Target

EMPLOYEES = {
    "EMP-SUPPORT-01": {"role": "support", "country": "US", "device_id": "DEV-11", "ip": "10.0.0.11"},
    "EMP-DEV-01": {"role": "developer", "country": "US", "device_id": "DEV-12", "ip": "10.0.0.22"},
    "EMP-ADMIN-01": {"role": "admin", "country": "US", "device_id": "DEV-13", "ip": "10.0.0.33"},
}

# Defaults for outside visitors (they are not employees)
EXTERNAL_DEFAULTS = {"role": "external", "device_id": "NONE", "ip": "0.0.0.0", "country": "XX"}

# number machine which gives number countings
_counter = 0


def nextid() -> str:
    global _counter
    _counter += 1
    return f"EVT-{_counter:05d}"


# FORM FILLING
def make_event(event_type, user_id, timestamp, resource_id="app", resource_type="service",
               device_id=None, ip=None, country=None, role=None, metadata=None):
    employee = EMPLOYEES.get(user_id, EXTERNAL_DEFAULTS)
    return Event(
        event_id=nextid(),
        event_type=event_type,
        timestamp=timestamp,
        actor=Actor(
            user_id=user_id,
            role=role or employee["role"],
        ),
        source=Source(
            ip=ip or employee["ip"],
            device_id=device_id or employee["device_id"],
            country=country or employee["country"],
        ),
        target=Target(
            resource_id=resource_id,
            resource_type=resource_type,
        ),
        metadata=metadata or {},
    )

def normal_day(day, seed=None):
    """Create a normal working day of events. A seed makes the result repeatable."""
    if seed is not None:
        random.seed(seed)
    events = []
    for user_id in EMPLOYEES : #one login time in morning for each employee between 9:00 and 9:40 randomly
        login_time = day.replace(hour = 9, minute= 0 , second=0) + timedelta(minutes=random.randint(0, 40))
        events.append(make_event(EventType.LOGIN,user_id,login_time))

        #few normal work actions during day
        number_of_actions = random.randint(3,8)
        for _ in range(number_of_actions) :
            action_time = login_time + timedelta(minutes = random.randint(10,480))
            events.append(
                make_event(
                    EventType.RESOURCE_ACCESS,
                    user_id,
                    action_time,
                    resource_id = "staging-db",
                    resource_type = "database"
                )
            )
        #3 ALL EVENTS ALLTOGETHER LIKE A REAL LOG IN TIME ORDER
    events.sort(key = lambda event : event.timestamp)
    return events

def account_takeover(start_time, victim_id = "EMP-SUPPORT-01"):
    """AN ATTACKER TAKES OVER A SUPPORT ACCOUNT AND CLIMBS UP TO ADMIN"""
    # THE ATTACKER'S OWN DEVICE,IP,COUNTRY 
    attacker = {"device_id": "DEV-99", "ip": "198.51.100.24", "country": "PK"}
    events = []

    #1 login from new device and new country
    current_time = start_time
    events.append(make_event(
        EventType.LOGIN,
        victim_id,
        current_time,
        **attacker,))

    #2 two step login changed (MFA_CHANGED)
    current_time += timedelta(minutes = 1)
    events.append(make_event(EventType.MFA_CHANGED,victim_id,current_time,**attacker))

    #3  a new API key created 
    current_time += timedelta(minutes = 1)
    events.append(make_event(EventType.API_KEY_CREATED,victim_id,current_time,
                            resource_id = "KEY-777" , resource_type = "api_key", **attacker))
                            
    #4 the role jumps from support to admin
    current_time += timedelta(minutes = 2)
    events.append(make_event(EventType.ROLE_CHANGED,victim_id,current_time,
                            role = "admin", metadata = {"old_role": "support", "new_role": "admin"}, **attacker)) 

    #5 the payment database is accessed
    current_time += timedelta(minutes = 1)
    events.append(make_event(EventType.RESOURCE_ACCESS,victim_id,current_time,
                            role = "admin", resource_id = "prod-payments-db", resource_type = "database", **attacker))
    return events 

def brute_force_attack (start_time , victim_id = "EMP-DEV-01" , attempts = 6):
    """An attacker keeps guessing the password of one account"""
    #the attacker's own device,IP and country 
    attacker = {"device_id": "DEV-77", "ip": "203.0.113.50", "country": "BR"}
    events = []
    
    current_time = start_time
    for _ in range(attempts):
        events.append(make_event(EventType.LOGIN_FAILED , victim_id , current_time, **attacker))
        current_time += timedelta(seconds=30) 
                            
    return events    

def web_request(timestamp, visitor_ip, path, query, status=200):
    """One request to the website, made by an outside visitor."""
    return make_event(
        EventType.WEB_REQUEST,
        f"ANON-{visitor_ip}",
        timestamp,
        resource_id=path,
        resource_type="web_page",
        ip=visitor_ip,
        metadata={"method": "GET", "query": query, "status": status},
    )


def normal_web_requests(day):
    """Ordinary visitors using the website (this is the background noise)."""
    visits = [
        ("198.51.100.21", "/search", "q=blue+shoes"),
        ("198.51.100.22", "/search", "q=men%27s+shoes"),   # an apostrophe, but harmless
        ("198.51.100.23", "/products", "page=2"),
        ("198.51.100.24", "/search", "q=laptop+bag"),
        ("198.51.100.25", "/checkout", "step=payment"),
    ]
    events = []
    current_time = day.replace(hour=10, minute=0)
    for visitor_ip, path, query in visits:
        events.append(web_request(current_time, visitor_ip, path, query))
        current_time += timedelta(minutes=7)
    return events


def sql_injection_attack(start_time, attacker_ip="198.51.100.7"):
    """An outsider tries SQL injection strings in the search box."""
    queries = [
        "q=%27%20OR%20%271%27%3D%271",
        "q=1 UNION SELECT name, pass FROM users",
        "q=1; DROP TABLE users",
    ]
    events = []
    current_time = start_time
    for query in queries:
        events.append(web_request(current_time, attacker_ip, "/search", query))
        current_time += timedelta(seconds=20)
    return events

def xss_attack(start_time, attacker_ip="198.51.100.8"):
    """an outsider tries to inject a cross-site scripting payload into the search box."""
    queries = [
        "q=<script>alert('1')</script>",
        "q=<img src=x onerror=alert('1')>",
        "q=javascript:alert('1')",
    ]
    events = []
    current_time = start_time
    for query in queries:
        events.append(web_request(current_time, attacker_ip, "/search", query))
        current_time += timedelta(seconds=20)
    return events


def path_traversal_attack(start_time, attacker_ip="198.51.100.9"):
    """An outsider tries to read files outside the website folder."""
    queries = [
        "file=../../etc/passwd",
        "file=..%2F..%2Fetc%2Fpasswd",
        "file=..\\..\\windows\\win.ini",
    ]
    events = []
    current_time = start_time
    for query in queries:
        events.append(web_request(current_time, attacker_ip, "/download", query))
        current_time += timedelta(seconds=20)
    return events