from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.schemas.attack_execution import AttackExecutionResponse
from app.services.attack_execution_service import AttackExecutionService
from app.services.attack_service import AttackService
from app.services.campaign_service import CampaignService


router = APIRouter(
    prefix="/attack-executions",
    tags=["Attack Executions"],
)


def can_access_campaign(current_user, campaign) -> bool:
    return (
        current_user.role == "admin"
        or current_user.id == campaign.created_by
    )


def get_execution_attack(
    db: Session,
    execution,
):
    attack = AttackService.get_by_id(
        db,
        execution.attack_id,
    )

    if attack is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack not found",
        )

    return attack


def get_attack_campaign(
    db: Session,
    attack,
):
    campaign = CampaignService.get_by_id(
        db,
        attack.campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    return campaign


@router.get(
    "/",
    response_model=list[AttackExecutionResponse],
)
def get_attack_executions(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role == "admin":
        return AttackExecutionService.get_all(db)

    campaigns = CampaignService.get_by_user(
        db,
        current_user.id,
    )

    campaign_ids = {
        campaign.id
        for campaign in campaigns
    }

    attacks = AttackService.get_all(db)

    user_attack_ids = {
        attack.id
        for attack in attacks
        if attack.campaign_id in campaign_ids
    }

    executions = AttackExecutionService.get_all(db)

    return [
        execution
        for execution in executions
        if execution.attack_id in user_attack_ids
    ]


@router.get(
    "/attack/{attack_id}",
    response_model=list[AttackExecutionResponse],
)
def get_executions_by_attack(
    attack_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    attack = AttackService.get_by_id(
        db,
        attack_id,
    )

    if attack is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack not found",
        )

    campaign = get_attack_campaign(
        db,
        attack,
    )

    if not can_access_campaign(
        current_user,
        campaign,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access these executions",
        )

    return AttackExecutionService.get_by_attack(
        db,
        attack_id,
    )


@router.get(
    "/conversation/{conversation_id}",
    response_model=list[AttackExecutionResponse],
)
def get_executions_by_conversation(
    conversation_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    executions = AttackExecutionService.get_by_conversation(
        db,
        conversation_id,
    )

    if current_user.role == "admin":
        return executions

    accessible_executions = []

    for execution in executions:
        attack = AttackService.get_by_id(
            db,
            execution.attack_id,
        )

        if attack is None:
            continue

        campaign = CampaignService.get_by_id(
            db,
            attack.campaign_id,
        )

        if campaign is None:
            continue

        if campaign.created_by == current_user.id:
            accessible_executions.append(execution)

    return accessible_executions


@router.get(
    "/{execution_id}",
    response_model=AttackExecutionResponse,
)
def get_attack_execution(
    execution_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    execution = AttackExecutionService.get_by_id(
        db,
        execution_id,
    )

    if execution is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack execution not found",
        )

    attack = get_execution_attack(
        db,
        execution,
    )

    campaign = get_attack_campaign(
        db,
        attack,
    )

    if not can_access_campaign(
        current_user,
        campaign,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this execution",
        )

    return execution


@router.delete(
    "/{execution_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_attack_execution(
    execution_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    execution = AttackExecutionService.get_by_id(
        db,
        execution_id,
    )

    if execution is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack execution not found",
        )

    attack = get_execution_attack(
        db,
        execution,
    )

    campaign = get_attack_campaign(
        db,
        attack,
    )

    if not can_access_campaign(
        current_user,
        campaign,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this execution",
        )

    AttackExecutionService.delete(
        db,
        execution,
    )