from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.application import Application
from app.schemas.application import ApplicationCreate, ApplicationUpdate


class ApplicationService:

    @staticmethod
    def create(
        db: Session,
        application_data: ApplicationCreate,
        created_by: UUID,
    ) -> Application:

        application = Application(
            **application_data.model_dump(),
            created_by=created_by,
        )

        db.add(application)
        db.commit()
        db.refresh(application)

        return application

    @staticmethod
    def get_by_id(
        db: Session,
        application_id: UUID,
    ) -> Application | None:

        statement = select(Application).where(
            Application.id == application_id
        )

        return db.scalar(statement)

    @staticmethod
    def get_all(
        db: Session,
        user_id: UUID | None = None,
        is_admin: bool = False,
    ) -> list[Application]:

        statement = select(Application)

        if not is_admin:
            statement = statement.where(
                Application.created_by == user_id
            )

        statement = statement.order_by(Application.name)

        return list(db.scalars(statement).all())

    @staticmethod
    def update(
        db: Session,
        application: Application,
        application_data: ApplicationUpdate,
    ) -> Application:

        update_data = application_data.model_dump(
            exclude_unset=True
        )

        for field, value in update_data.items():
            setattr(application, field, value)

        db.commit()
        db.refresh(application)

        return application

    @staticmethod
    def delete(
        db: Session,
        application: Application,
    ) -> None:

        db.delete(application)
        db.commit()