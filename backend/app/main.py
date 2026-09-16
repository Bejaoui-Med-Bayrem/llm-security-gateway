from fastapi import FastAPI

app = FastAPI(
    title="LLM Security Gateway",
    description="LLM Red Teaming and Security Gateway Platform",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "llm-security-gateway",
    }