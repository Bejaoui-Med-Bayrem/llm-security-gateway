from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


def validate_endpoint_url(value: str) -> str:
    """
    endpoint_url is the target's base URL (e.g. http://127.0.0.1:8001);
    the adapter appends the API path itself.
    """

    value = value.strip()
    parts = urlsplit(value)

    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(
            "endpoint_url must be an http(s) URL, e.g. http://127.0.0.1:8001"
        )

    if parts.query or parts.fragment:
        raise ValueError(
            "endpoint_url must not contain a query string or fragment"
        )

    if len(value) > 500:
        raise ValueError("endpoint_url must be at most 500 characters")

    return value.rstrip("/")


class ApplicationBase(BaseModel):
    name: str
    description: str | None = None
    endpoint_url: str
    model_name: str
    application_type: str
    is_active: bool = True


class ApplicationCreate(ApplicationBase):

    @field_validator("endpoint_url")
    @classmethod
    def check_endpoint_url(cls, value: str) -> str:
        return validate_endpoint_url(value)


class ApplicationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    endpoint_url: str | None = None
    model_name: str | None = None
    application_type: str | None = None
    is_active: bool | None = None

    @field_validator("endpoint_url")
    @classmethod
    def check_endpoint_url(cls, value: str | None) -> str | None:
        if value is None:
            return value

        return validate_endpoint_url(value)


class ApplicationResponse(ApplicationBase):
    id: UUID
    created_by: UUID

    model_config = ConfigDict(from_attributes=True)
