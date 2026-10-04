import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, Float, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Evaluation(Base):
    __tablename__ = "evaluations"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    total_attacks: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    successful_attacks: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    blocked_attacks: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    detected_attacks: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    false_positives: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    attack_success_rate: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    detection_rate: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    false_positive_rate: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    average_latency_ms: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )