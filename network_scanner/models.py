# network_scanner/models.py
from typing import TypedDict, List, Optional

class DeviceInfo(TypedDict):
    ip: str
    mac: Optional[str]
    vendor: Optional[str]
    hostname: Optional[str]
    os: Optional[str]
    status: str
    source: str
    ports: Optional[str] # Podría ser List[Dict] si quieres más detalle