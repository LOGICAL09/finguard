from datetime import datetime
from enum import Enum
from pydantic import BaseModel , Field  
# ---------- 1. Allowed actions (a fixed list) ----------
# Only these 7 actions are allowed.
class EventType(str,Enum):
    LOGIN =  "LOGIN"
    LOGIN_FAILED =  "LOGIN_FAILED"
    MFA_CHANGED =  "MFA_CHANGED" # TWO STEP LOGGIN CHANGED
    API_KEY_CREATED = "API_KEY_CREATED"
    ROLE_CHANGED = "ROLE_CHANGED"
    RESOURCE_ACCESS = "RESOURCE_ACCESS" #DATABASE OPENED
    PAYMENT = "PAYMENT"
# ---------- 2. WHO did it? ----------
class Actor(BaseModel):
    user_id: str    
    role : str
#---------- 3. WHERE did it come from? ----------
class Source(BaseModel):
    ip : str 
    device_id : str
    country : str
# ---------- 4. WHAT was touched? ----------
class Target(BaseModel):
    resource_id: str #name of the file
    resource_type: str #its datatype like db or api
# ---------- 5. The full diary line ----------
class Event (BaseModel):
    event_id: str
    event_type : EventType #from the list of allowed actions
    actor : Actor
    source : Source
    target : Target
    timestamp : datetime
    metadata: dict = Field(default_factory=dict) #extra information about the event, like payment amount, or db name
