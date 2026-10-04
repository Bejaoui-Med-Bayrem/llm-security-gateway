from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    # No minimum: accounts created before password rules existed must
    # still be able to log in. The maximum bounds the Argon2 input.
    password: str = Field(max_length=1024)
