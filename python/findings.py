from dataclasses import dataclass

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
REGION = "eu-west-2"   



@dataclass
class Finding:
    severity: str    
    cis_id: str      
    resource: str    
    issue: str 
    def to_line(self) -> str:
        return f"{self.severity:<6} | CIS {self.cis_id:<4} | {self.resource} | {self.issue}"


