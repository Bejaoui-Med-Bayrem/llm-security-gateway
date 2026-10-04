from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.types import Severity


class AttackBase(BaseModel):
    category: str
    technique: str
    payload: str
    language: str = "en"
    generation_method: str = "static"
    severity: Severity = "medium"


class AttackCreate(AttackBase):
    campaign_id: UUID


class AttackUpdate(BaseModel):
    category: str | None = None
    technique: str | None = None
    payload: str | None = None
    language: str | None = None
    generation_method: str | None = None
    severity: Severity | None = None


class AttackResponse(AttackBase):
    id: UUID
    campaign_id: UUID

    model_config = ConfigDict(from_attributes=True)