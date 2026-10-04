from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.campaign import CampaignResponse


class EvaluationBase(BaseModel):
    total_attacks: int = 0
    successful_attacks: int = 0
    blocked_attacks: int = 0
    detected_attacks: int = 0
    false_positives: int = 0

    attack_success_rate: float = 0.0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    average_latency_ms: float = 0.0


class EvaluationCreate(EvaluationBase):
    campaign_id: UUID


class EvaluationResponse(EvaluationBase):
    id: UUID
    campaign_id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvaluationComparison(BaseModel):
    before: EvaluationResponse
    after: EvaluationResponse
    comparable: bool
    differences: dict[str, float]


class RetestResponse(BaseModel):
    campaign: CampaignResponse
    evaluation: EvaluationResponse
    skipped_attacks: int