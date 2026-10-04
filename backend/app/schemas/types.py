"""Allowed values for fields stored as plain strings in the database."""
from typing import Literal


UserRole = Literal["user", "admin"]

CampaignStatus = Literal[
    "pending",
    "running",
    "completed",
    "failed",
    "cancelled",
]

Severity = Literal["low", "medium", "high", "critical"]

# Written only by the Gateway. FLAG is only produced in monitor mode.
GatewayAction = Literal["ALLOW", "FLAG", "BLOCK"]