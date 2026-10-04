from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.types import GatewayAction


class GatewayDecisionBase(BaseModel):
    action: GatewayAction
    risk_score: float
    detector: str
    reason: str | None = None
    matched_rule: str | None = None
    processing_time_ms: int | None = None


class GatewayDecisionCreate(GatewayDecisionBase):
    execution_id: UUID


class GatewayDecisionResponse(GatewayDecisionBase):
    id: UUID
    execution_id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
