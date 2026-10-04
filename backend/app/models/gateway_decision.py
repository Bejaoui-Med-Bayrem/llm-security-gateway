import uuid
from datetime import datetime

from sqlalchemy import String, Text, ForeignKey, Float, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class GatewayDecision(Base):
    __tablename__ = "gateway_decisions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )

    execution_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_executions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    detector: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    matched_rule: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    processing_time_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )