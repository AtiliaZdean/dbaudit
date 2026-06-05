# file for shared data structures used across the whole tool
# a finding is what every check returns: one issue it discovered (or didnt)

from dataclasses import dataclass   # dataclass auto generates __init__ for us
from enum import Enum   # Enum = a fixed set of named values

# severity levels - ordered from least to most critical
class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# a single finding from one audit check
# education auto-creates __init__ so dont have to write it manually
@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    passed: bool = False

    def __str__(self):
        # makes print)finding) readable
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] [{ self.severity.value }] { self.title }"