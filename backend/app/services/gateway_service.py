from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.gateway_decision import GatewayDecision
from app.schemas.gateway_decision import GatewayDecisionCreate


class GatewayService:

    @staticmethod
    def create(
        db: Session,
        decision_data: GatewayDecisionCreate,
    ) -> GatewayDecision:

        decision = GatewayDecision(
            **decision_data.model_dump()
        )

        db.add(decision)
        db.commit()
        db.refresh(decision)

        return decision

    @staticmethod
    def get_by_id(
        db: Session,
        decision_id: UUID,
    ) -> GatewayDecision | None:

        statement = select(GatewayDecision).where(
            GatewayDecision.id == decision_id
        )

        return db.scalar(statement)

    @staticmethod
    def get_by_execution(
        db: Session,
        execution_id: UUID,
    ) -> GatewayDecision | None:

        statement = select(GatewayDecision).where(
            GatewayDecision.execution_id == execution_id
        )

        return db.scalar(statement)

    @staticmethod
    def get_all(
        db: Session,
    ) -> list[GatewayDecision]:

        statement = select(GatewayDecision).order_by(
            GatewayDecision.created_at.desc()
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def delete(
        db: Session,
        decision: GatewayDecision,
    ) -> None:

        db.delete(decision)
        db.commit()