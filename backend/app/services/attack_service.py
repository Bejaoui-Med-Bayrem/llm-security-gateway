from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attack import Attack
from app.schemas.attack import AttackCreate, AttackUpdate


class AttackService:

    @staticmethod
    def create(
        db: Session,
        attack_data: AttackCreate,
    ) -> Attack:

        attack = Attack(
            **attack_data.model_dump()
        )

        db.add(attack)
        db.commit()
        db.refresh(attack)

        return attack

    @staticmethod
    def get_by_id(
        db: Session,
        attack_id: UUID,
    ) -> Attack | None:

        statement = select(Attack).where(
            Attack.id == attack_id
        )

        return db.scalar(statement)

    @staticmethod
    def get_all(
        db: Session,
    ) -> list[Attack]:

        statement = select(Attack).order_by(
            Attack.category
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def get_by_campaign(
        db: Session,
        campaign_id: UUID,
    ) -> list[Attack]:

        statement = select(Attack).where(
            Attack.campaign_id == campaign_id
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def get_by_category(
        db: Session,
        category: str,
    ) -> list[Attack]:

        statement = select(Attack).where(
            Attack.category == category
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def copy_to_campaign(
        db: Session,
        source_campaign_id: UUID,
        target_campaign_id: UUID,
    ) -> list[Attack]:
        """Copy every attack of a campaign into another one, unchanged."""

        copies = []

        for source in AttackService.get_by_campaign(
            db,
            source_campaign_id,
        ):
            attack_data = AttackCreate(
                campaign_id=target_campaign_id,
                category=source.category,
                technique=source.technique,
                payload=source.payload,
                language=source.language,
                generation_method=source.generation_method,
                severity=source.severity,
            )

            copies.append(
                Attack(**attack_data.model_dump())
            )

        db.add_all(copies)
        db.commit()

        for copy in copies:
            db.refresh(copy)

        return copies

    @staticmethod
    def update(
        db: Session,
        attack: Attack,
        attack_data: AttackUpdate,
    ) -> Attack:

        update_data = attack_data.model_dump(
            exclude_unset=True
        )

        for field, value in update_data.items():
            setattr(attack, field, value)

        db.commit()
        db.refresh(attack)

        return attack

    @staticmethod
    def delete(
        db: Session,
        attack: Attack,
    ) -> None:

        db.delete(attack)
        db.commit()