from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.types import UserRole


class UserBase(BaseModel):
    email: EmailStr
    full_name: str


class UserCreate(UserBase):
    # max_length bounds the Argon2 input so huge passwords cannot be
    # used to tie up the server.
    password: str = Field(min_length=8, max_length=128)


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserResponse(UserBase):
    id: UUID
    role: UserRole
    is_active: bool

    model_config = ConfigDict(from_attributes=True)