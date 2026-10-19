from pydantic import BaseModel
from typing import Dict, List


class DayBucket(BaseModel):
    date: str  # ISO date
    total: int
    completed: int
    denied: int
    failed: int


class DashboardStats(BaseModel):
    # Aggregates over the window
    window_days: int

    # Time series: LLM calls through the gateway
    calls_by_day: List[DayBucket]

    # Distribution maps
    calls_by_status: Dict[str, int]
    incidents_by_severity: Dict[str, int]

    # Scalar counters
    total_calls: int
    total_incidents: int
    pending_approvals: int
    total_policies: int
