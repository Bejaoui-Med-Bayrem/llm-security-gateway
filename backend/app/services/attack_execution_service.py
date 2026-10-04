from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attack import Attack
from app.models.attack_execution import AttackExecution
from app.schemas.attack_execution import AttackExecutionCreate


class AttackExecutionService:

    @staticmethod
    def get_conversation_history(
        db: Session,
        conversation_id: str,
        campaign_id: UUID,
    ) -> list[AttackExecution]:
        """
        Turns of a conversation that actually reached the target, oldest first.

        Scoped to one campaign so a conversation_id reused by another user
        never leaks their turns. Blocked turns and turns without a response
        are excluded: the target never saw them.
        """

        statement = (
            select(AttackExecution)
            .join(Attack, AttackExecution.attack_id == Attack.id)
            .where(
                AttackExecution.conversation_id == conversation_id,
                Attack.campaign_id == campaign_id,
                AttackExecution.gateway_action == "ALLOW",
                AttackExecution.response.is_not(None),
            )
            .order_by(AttackExecution.executed_at)
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def get_conversation_scores(
        db: Session,
        conversation_id: str,
        campaign_id: UUID,
    ) -> list[float]:
        """
        Risk scores of every turn of a conversation, blocked turns included,
        oldest first. Used by the policy engine for session escalation.

        Scoped to one campaign, like get_conversation_history.
        """

        statement = (
            select(AttackExecution.risk_score)
            .join(Attack, AttackExecution.attack_id == Attack.id)
            .where(
                AttackExecution.conversation_id == conversation_id,
                Attack.campaign_id == campaign_id,
            )
            .order_by(AttackExecution.executed_at)
        )

        return [float(score or 0) for score in db.scalars(statement).all()]

    @staticmethod
    def create(
        db: Session,
        execution_data: AttackExecutionCreate,
    ) -> AttackExecution:

        execution = AttackExecution(
            **execution_data.model_dump()
        )

        db.add(execution)
        db.commit()
        db.refresh(execution)

        return execution

    @staticmethod
    def get_by_id(
        db: Session,
        execution_id: UUID,
    ) -> AttackExecution | None:

        statement = select(AttackExecution).where(
            AttackExecution.id == execution_id
        )

        return db.scalar(statement)

    @staticmethod
    def get_all(
        db: Session,
    ) -> list[AttackExecution]:

        statement = select(AttackExecution).order_by(
            AttackExecution.executed_at.desc()
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def get_by_attack(
        db: Session,
        attack_id: UUID,
    ) -> list[AttackExecution]:

        statement = select(AttackExecution).where(
            AttackExecution.attack_id == attack_id
        ).order_by(
            AttackExecution.executed_at.desc()
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def get_by_conversation(
        db: Session,
        conversation_id: str,
    ) -> list[AttackExecution]:

        statement = select(AttackExecution).where(
            AttackExecution.conversation_id == conversation_id
        ).order_by(
            AttackExecution.executed_at
        )

        return list(db.scalars(statement).all())

    @staticmethod
    def delete(
        db: Session,
        execution: AttackExecution,
    ) -> None:

        db.delete(execution)
        db.commit()