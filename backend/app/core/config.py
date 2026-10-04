import os

from dotenv import load_dotenv
from sqlalchemy.engine import URL

load_dotenv()


class Settings:
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # API server
    APP_HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))

    # Database
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "llm_security")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "llm_security")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "")
    # 127.0.0.1, not localhost: Postgres is published on IPv4 loopback
    # only, and "localhost" tries ::1 first, stalling every connection.
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "127.0.0.1")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "15432"))

    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )

    # AI Goat
    AIGOAT_BASE_URL: str = os.getenv(
        "AIGOAT_BASE_URL",
        "http://127.0.0.1:8001",
    )
    AIGOAT_TOKEN: str = os.getenv("AIGOAT_TOKEN", "")

    @property
    def DATABASE_URL(self) -> URL:
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        )

    def validate(self) -> None:
        """
        Refuse to start with a broken configuration instead of failing
        on the first request (e.g. every login returning 500).
        """

        errors = []
        generate_hint = (
            'generate one with: python -c "import secrets; '
            'print(secrets.token_urlsafe(48))"'
        )

        if not self.JWT_SECRET_KEY:
            errors.append(f"JWT_SECRET_KEY is not set; {generate_hint}")
        elif self.JWT_SECRET_KEY == "change_me":
            errors.append(
                "JWT_SECRET_KEY still has the .env.example placeholder; "
                f"{generate_hint}"
            )
        elif (
            self.JWT_ALGORITHM.startswith("HS")
            and len(self.JWT_SECRET_KEY.encode()) < 32
        ):
            errors.append(
                f"JWT_SECRET_KEY must be at least 32 bytes for "
                f"{self.JWT_ALGORITHM}; {generate_hint}"
            )

        if not self.POSTGRES_PASSWORD:
            errors.append("POSTGRES_PASSWORD is not set.")

        if errors:
            raise RuntimeError(
                "Invalid configuration (check your .env):\n  - "
                + "\n  - ".join(errors)
            )


settings = Settings()
