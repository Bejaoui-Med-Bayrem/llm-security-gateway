from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.schemas.gateway_decision import GatewayDecisionResponse
from app.services.attack_execution_service import AttackExecutionService
from app.services.attack_service import AttackService
from app.services.campaign_service import CampaignService
from app.services.gateway_service import GatewayService


router = APIRouter(
    prefix="/gateway-decisions",
    tags=["Gateway Decisions"],
)


def can_access_campaign(current_user, campaign) -> bool:
    return (
        current_user.role == "admin"
        or current_user.id == campaign.created_by
    )


def get_decision_execution(db: Session, decision):
    execution = AttackExecutionService.get_by_id(
        db,
        decision.execution_id,
    )

    if execution is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack execution not found",
        )

    return execution


def get_execution_attack(db: Session, execution):
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


def get_attack_campaign(db: Session, attack):
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
    response_model=list[GatewayDecisionResponse],
)
def get_gateway_decisions(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    decisions = GatewayService.get_all(db)

    if current_user.role == "admin":
        return decisions

    accessible_decisions = []

    for decision in decisions:
        execution = AttackExecutionService.get_by_id(
            db,
            decision.execution_id,
        )

        if execution is None:
            continue

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
            accessible_decisions.append(decision)

    return accessible_decisions


@router.get(
    "/execution/{execution_id}",
    response_model=GatewayDecisionResponse,
)
def get_gateway_decision_by_execution(
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

    attack = get_execution_attack(db, execution)
    campaign = get_attack_campaign(db, attack)

    if not can_access_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this gateway decision",
        )

    decision = GatewayService.get_by_execution(
        db,
        execution_id,
    )

    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway decision not found",
        )

    return decision


@router.get(
    "/{decision_id}",
    response_model=GatewayDecisionResponse,
)
def get_gateway_decision(
    decision_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    decision = GatewayService.get_by_id(
        db,
        decision_id,
    )

    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway decision not found",
        )

    execution = get_decision_execution(db, decision)
    attack = get_execution_attack(db, execution)
    campaign = get_attack_campaign(db, attack)

    if not can_access_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this gateway decision",
        )

    return decision


@router.delete(
    "/{decision_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_gateway_decision(
    decision_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    decision = GatewayService.get_by_id(
        db,
        decision_id,
    )

    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway decision not found",
        )

    execution = get_decision_execution(db, decision)
    attack = get_execution_attack(db, execution)
    campaign = get_attack_campaign(db, attack)

    if not can_access_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this gateway decision",
        )

    GatewayService.delete(
        db,
        decision,
    )