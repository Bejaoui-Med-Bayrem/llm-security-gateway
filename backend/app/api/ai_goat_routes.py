from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.adapters.ai_goat import AIGoatError
from app.core.auth import get_current_user
from app.core.database import get_db
from app.schemas.ai_goat import (
    AIGoatExecutionRequest,
    AIGoatExecutionResponse,
)
from app.services.gateway_execution_service import (
    GatewayExecutionError,
    GatewayExecutionService,
)


router = APIRouter(
    prefix="/ai-goat",
    tags=["AI Goat"],
)


@router.post(
    "/execute",
    response_model=AIGoatExecutionResponse,
    status_code=status.HTTP_201_CREATED,
)
def execute_attack_with_ai_goat(
    execution_data: AIGoatExecutionRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return GatewayExecutionService.execute(
            db,
            attack_id=execution_data.attack_id,
            current_user=current_user,
            conversation_id=execution_data.conversation_id,
            defense_mode=execution_data.defense_mode,
        )

    except GatewayExecutionError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=str(exc),
        )

    except AIGoatError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )