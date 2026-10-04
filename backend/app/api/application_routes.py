from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.schemas.application import (
    ApplicationCreate,
    ApplicationResponse,
    ApplicationUpdate,
)
from app.services.application_service import ApplicationService


router = APIRouter(
    prefix="/applications",
    tags=["Applications"],
)


def can_manage_application(current_user, application) -> bool:
    return (
        current_user.role == "admin"
        or current_user.id == application.created_by
    )


@router.post(
    "/",
    response_model=ApplicationResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_application(
    application_data: ApplicationCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return ApplicationService.create(
        db,
        application_data,
        current_user.id,
    )


@router.get(
    "/",
    response_model=list[ApplicationResponse],
)
def get_applications(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return ApplicationService.get_all(
        db,
        current_user.id,
        current_user.role == "admin",
    )


@router.get(
    "/{application_id}",
    response_model=ApplicationResponse,
)
def get_application(
    application_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    application = ApplicationService.get_by_id(
        db,
        application_id,
    )

    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )

    if not can_manage_application(current_user, application):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this application",
        )

    return application


@router.put(
    "/{application_id}",
    response_model=ApplicationResponse,
)
def update_application(
    application_id: UUID,
    application_data: ApplicationUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    application = ApplicationService.get_by_id(
        db,
        application_id,
    )

    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )

    if not can_manage_application(current_user, application):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to modify this application",
        )

    return ApplicationService.update(
        db,
        application,
        application_data,
    )


@router.delete(
    "/{application_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_application(
    application_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    application = ApplicationService.get_by_id(
        db,
        application_id,
    )

    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )

    if not can_manage_application(current_user, application):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this application",
        )

    ApplicationService.delete(
        db,
        application,
    )