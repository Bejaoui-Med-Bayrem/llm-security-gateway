from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import get_current_user
from app.schemas.user import UserResponse, UserUpdate
from app.services.user_service import UserService


router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/", response_model=list[UserResponse])
def get_users(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return UserService.get_all(db)


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    user = UserService.get_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if current_user.role != "admin" and current_user.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this user",
        )

    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: UUID,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    user = UserService.get_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    is_admin = current_user.role == "admin"
    is_owner = current_user.id == user.id

    if not is_admin and not is_owner:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to modify this user",
        )

    if not is_admin:
        if user_data.role is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot change your role",
            )

        if user_data.is_active is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot change your active status",
            )

    if user_data.email is not None and user_data.email != user.email:
        existing_user = UserService.get_by_email(db, user_data.email)

        if existing_user is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

    loses_admin_access = (
        (user_data.role is not None and user_data.role != "admin")
        or user_data.is_active is False
    )

    if loses_admin_access and UserService.is_last_active_admin(db, user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This is the last active admin; promote another admin first",
        )

    return UserService.update(db, user, user_data)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    user = UserService.get_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    is_admin = current_user.role == "admin"
    is_owner = current_user.id == user.id

    if not is_admin and not is_owner:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this user",
        )

    if UserService.is_last_active_admin(db, user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This is the last active admin; promote another admin first",
        )

    applications, campaigns = UserService.count_owned_resources(
        db,
        user.id,
    )

    if applications or campaigns:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"User owns {applications} application(s) and "
                f"{campaigns} campaign(s). Delete them first, "
                "or deactivate the user instead."
            ),
        )

    UserService.delete(db, user)