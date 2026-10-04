from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.campaign import Campaign
from app.schemas.campaign import CampaignCreate, CampaignUpdate


class CampaignService:

    @staticmethod
    def create(
        db: Session,
        campaign_data: CampaignCreate,
        created_by: UUID,
    ) -> Campaign:

        campaign = Campaign(
            **campaign_data.model_dump(),
            created_by=created_by,
        )

        db.add(campaign)
        db.commit()
        db.refresh(campaign)

        return campaign

    @staticmethod
    def clone(
        db: Session,
        campaign: Campaign,
        created_by: UUID,
        name: str | None = None,
    ) -> Campaign:
        """New pending campaign on the same application, without attacks."""

        copy = Campaign(
            name=name or f"{campaign.name} (copy)",
            description=campaign.description,
            status="pending",
            application_id=campaign.application_id,
            created_by=created_by,
        )

        db.add(copy)
        db.commit()
        db.refresh(copy)

        return copy

    @staticmethod
    def get_by_id(
        db: Session,
        campaign_id: UUID,
    ) -> Campaign | None:

        statement = select(Campaign).where(
            Campaign.id == campaign_id
        )

        return db.scalar(statement)

    @staticmethod
    def get_all(
        db: Session,
        user_id: UUID | None = None,
        is_admin: bool = False,
    ) -> list[Campaign]:

        statement = select(Campaign)

        if not is_admin:
            statement = statement.where(
                Campaign.created_by == user_id
            )

        statement = statement.order_by(Campaign.name)

        return list(db.scalars(statement).all())

    @staticmethod
    def get_by_application(
        db: Session,
        application_id: UUID,
    ) -> list[Campaign]:

        statement = select(Campaign).where(
            Campaign.application_id == application_id
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def get_by_user(
        db: Session,
        user_id: UUID,
    ) -> list[Campaign]:

        statement = select(Campaign).where(
            Campaign.created_by == user_id
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def update(
        db: Session,
        campaign: Campaign,
        campaign_data: CampaignUpdate,
    ) -> Campaign:

        update_data = campaign_data.model_dump(
            exclude_unset=True
        )

        for field, value in update_data.items():
            setattr(campaign, field, value)

        db.commit()
        db.refresh(campaign)

        return campaign

    @staticmethod
    def delete(
        db: Session,
        campaign: Campaign,
    ) -> None:

        db.delete(campaign)
        db.commit()