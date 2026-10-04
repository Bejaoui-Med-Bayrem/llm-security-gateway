import os

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.api.ai_goat_routes import router as ai_goat_router
from app.api.application_routes import router as application_router
from app.api.attack_execution_routes import router as attack_execution_router
from app.api.attack_routes import router as attack_router
from app.api.auth_routes import router as auth_router
from app.api.campaign_routes import router as campaign_router
from app.api.evaluation_routes import router as evaluation_router
from app.api.gateway_decision_routes import router as gateway_decision_router
from app.api.user_routes import router as user_router
from app.core.config import settings


settings.validate()


def cors_origins() -> list[str]:
    raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    )

    return [origin.strip() for origin in raw.split(",") if origin.strip()]


app = FastAPI(
    title="LLM Security Gateway",
    description="LLM Red Teaming and Security Gateway Platform",
    version="0.1.0",
)


# The dashboard (Next.js, port 3000) calls this API from the browser.
# Authentication uses a Bearer header, not cookies, so credentials are
# not allowed and only the listed origins are accepted.
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# Safety net: a database constraint violation (duplicate email,
# reference still in use, ...) is a client conflict, not a server crash.
# The SQL error is not returned to avoid leaking schema details.
@app.exception_handler(IntegrityError)
def integrity_error_handler(request: Request, exc: IntegrityError):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            "detail": "The request conflicts with existing data.",
        },
    )


app.include_router(
    ai_goat_router,
    prefix="/api",
)

app.include_router(
    application_router,
    prefix="/api",
)

app.include_router(
    attack_execution_router,
    prefix="/api",
)

app.include_router(
    attack_router,
    prefix="/api",
)

app.include_router(
    auth_router,
    prefix="/api",
)

app.include_router(
    campaign_router,
    prefix="/api",
)

app.include_router(
    evaluation_router,
    prefix="/api",
)

app.include_router(
    gateway_decision_router,
    prefix="/api",
)

app.include_router(
    user_router,
    prefix="/api",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "llm-security-gateway",
    }


if __name__ == "__main__":
    import uvicorn

    # Runs on APP_PORT (8000 by default) so it does not collide
    # with AI Goat, which listens on port 8001.
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.ENVIRONMENT == "development",
    )