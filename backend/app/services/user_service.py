from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.application import Application
from app.models.campaign import Campaign
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate


class UserService:
    @staticmethod
    def create(
        db: Session,
        user_data: UserCreate,
        role: str = "user",
    ) -> User:
        password_hash = hash_password(user_data.password)

        user = User(
            email=user_data.email,
            full_name=user_data.full_name,
            role=role,
            is_active=True,
            password_hash=password_hash,
        )

        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def is_last_active_admin(db: Session, user: User) -> bool:
        if user.role != "admin" or not user.is_active:
            return False

        active_admins = db.scalar(
            select(func.count()).select_from(User).where(
                User.role == "admin",
                User.is_active.is_(True),
            )
        )

        return active_admins <= 1

    @staticmethod
    def get_by_id(db: Session, user_id: UUID) -> User | None:
        statement = select(User).where(User.id == user_id)
        return db.scalar(statement)

    @staticmethod
    def get_by_email(db: Session, email: str) -> User | None:
        statement = select(User).where(User.email == email)
        return db.scalar(statement)

    @staticmethod
    def get_all(db: Session) -> list[User]:
        statement = select(User).order_by(User.full_name)
        return list(db.scalars(statement).all())

    @staticmethod
    def update(
        db: Session,
        user: User,
        user_data: UserUpdate,
    ) -> User:
        update_data = user_data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            setattr(user, field, value)

        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def count_owned_resources(
        db: Session,
        user_id: UUID,
    ) -> tuple[int, int]:
        """
        Returns:
            applications,
            campaigns
        """

        applications = db.scalar(
            select(func.count()).select_from(Application).where(
                Application.created_by == user_id
            )
        )

        campaigns = db.scalar(
            select(func.count()).select_from(Campaign).where(
                Campaign.created_by == user_id
            )
        )

        return applications, campaigns

    @staticmethod
    def delete(db: Session, user: User) -> None:
        db.delete(user)
        db.commit()

