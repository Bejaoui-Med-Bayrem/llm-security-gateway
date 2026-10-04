import uuid
from datetime import datetime

from sqlalchemy import String, Text, ForeignKey, Boolean, Float, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AttackExecution(Base):
    __tablename__ = "attack_executions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )

    attack_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attacks.id", ondelete="CASCADE"),
        nullable=False,
    )

    request: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    response: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    conversation_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    gateway_action: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    attack_success: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    risk_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    latency_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    executed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )