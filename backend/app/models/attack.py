import uuid

from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Attack(Base):
    __tablename__ = "attacks"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    technique: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    payload: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    language: Mapped[str] = mapped_column(
        String(20),
        default="en",
        nullable=False,
    )

    generation_method: Mapped[str] = mapped_column(
        String(50),
        default="static",
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        default="medium",
        nullable=False,
    )