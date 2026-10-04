from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.types import CampaignStatus


class CampaignBase(BaseModel):
    name: str
    description: str | None = None
    status: CampaignStatus = "pending"


class CampaignCreate(CampaignBase):
    application_id: UUID


class CampaignUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: CampaignStatus | None = None
    application_id: UUID | None = None


class CampaignResponse(CampaignBase):
    id: UUID
    application_id: UUID
    created_by: UUID

    model_config = ConfigDict(from_attributes=True)