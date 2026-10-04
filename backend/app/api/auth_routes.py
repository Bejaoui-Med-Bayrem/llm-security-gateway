from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.rate_limit import login_rate_limiter
from app.schemas.auth import LoginRequest
from app.schemas.user import UserCreate, UserResponse
from app.services.user_service import UserService
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    verify_password,
)


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    existing_user = UserService.get_by_email(db, user_data.email)

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    return UserService.create(db, user_data)


@router.post("/login")
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown"

    retry_after = login_rate_limiter.retry_after(
        client_ip,
        login_data.email,
    )

    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = UserService.get_by_email(db, login_data.email)

    # Always run Argon2, even for unknown emails, so response timing
    # does not reveal which accounts exist.
    password_valid = verify_password(
        login_data.password,
        user.password_hash if user is not None else DUMMY_PASSWORD_HASH,
    )

    if user is None or not password_valid:
        login_rate_limiter.record_failure(
            client_ip,
            login_data.email,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Only reached with the correct password, so the account status
    # is never revealed to someone guessing.
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    login_rate_limiter.reset(
        client_ip,
        login_data.email,
    )

    access_token = create_access_token(
        {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

