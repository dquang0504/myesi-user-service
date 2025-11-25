from typing import Optional, Literal
from pydantic import BaseModel


class DashboardFieldTrend(BaseModel):
    total: Optional[int] = 0
    change: Optional[int] = 0
    trend: Optional[Literal["up", "down"]] = None


class SBOMField(BaseModel):
    scanned: Optional[int] = 0
    change: Optional[int] = 0


class DashboardStatsResponse(BaseModel):
    users: Optional[DashboardFieldTrend] = DashboardFieldTrend()
    projects: Optional[DashboardFieldTrend] = DashboardFieldTrend()
    vulnerabilities: Optional[DashboardFieldTrend] = DashboardFieldTrend()
    sboms: Optional[SBOMField] = SBOMField()
