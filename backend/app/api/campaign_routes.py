from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.schemas.campaign import (
    CampaignCreate,
    CampaignResponse,
    CampaignUpdate,
)
from app.schemas.evaluation import RetestResponse
from app.services.application_service import ApplicationService
from app.services.attack_service import AttackService
from app.services.campaign_service import CampaignService
from app.services.gateway_execution_service import GatewayExecutionError
from app.services.retest_service import RetestService


router = APIRouter(
    prefix="/campaigns",
    tags=["Campaigns"],
)


def can_manage_campaign(current_user, campaign) -> bool:
    return (
        current_user.role == "admin"
        or current_user.id == campaign.created_by
    )


def can_access_application(current_user, application) -> bool:
    return (
        current_user.role == "admin"
        or current_user.id == application.created_by
    )


def load_campaign_to_replay(db, current_user, campaign_id, action):
    campaign = CampaignService.get_by_id(
        db,
        campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_manage_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You are not allowed to {action} this campaign",
        )

    application = ApplicationService.get_by_id(
        db,
        campaign.application_id,
    )

    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )

    if not can_access_application(current_user, application):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to use this application",
        )

    return campaign


@router.post(
    "/",
    response_model=CampaignResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_campaign(
    campaign_data: CampaignCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    application = ApplicationService.get_by_id(
        db,
        campaign_data.application_id,
    )

    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )

    if not can_access_application(current_user, application):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to use this application",
        )

    return CampaignService.create(
        db,
        campaign_data,
        current_user.id,
    )


@router.get(
    "/",
    response_model=list[CampaignResponse],
)
def get_campaigns(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return CampaignService.get_all(
        db,
        current_user.id,
        current_user.role == "admin",
    )


@router.get(
    "/application/{application_id}",
    response_model=list[CampaignResponse],
)
def get_campaigns_by_application(
    application_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    application = ApplicationService.get_by_id(
        db,
        application_id,
    )

    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )

    if not can_access_application(current_user, application):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this application",
        )

    return CampaignService.get_by_application(
        db,
        application_id,
    )


@router.get(
    "/user/{user_id}",
    response_model=list[CampaignResponse],
)
def get_campaigns_by_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access these campaigns",
        )

    return CampaignService.get_by_user(
        db,
        user_id,
    )


@router.get(
    "/{campaign_id}",
    response_model=CampaignResponse,
)
def get_campaign(
    campaign_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    campaign = CampaignService.get_by_id(
        db,
        campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_manage_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this campaign",
        )

    return campaign


@router.post(
    "/{campaign_id}/clone",
    response_model=CampaignResponse,
    status_code=status.HTTP_201_CREATED,
)
def clone_campaign(
    campaign_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Copy a campaign and all its attacks into a new pending campaign."""

    campaign = load_campaign_to_replay(
        db,
        current_user,
        campaign_id,
        "clone",
    )

    copy = CampaignService.clone(
        db,
        campaign,
        current_user.id,
    )

    AttackService.copy_to_campaign(
        db,
        campaign.id,
        copy.id,
    )

    return copy


@router.post(
    "/{campaign_id}/retest",
    response_model=RetestResponse,
    status_code=status.HTTP_201_CREATED,
)
def retest_campaign(
    campaign_id: UUID,
    defense_mode: Literal["on", "off"] = "on",
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Replay the campaign's attacks against the current Gateway in a new
    campaign and return its evaluation. Allowed attacks wait for the target
    LLM, so a large campaign can take a while.

    defense_mode "off" sends the attacks straight to the target, without
    detection: it measures what the target suffers without protection.
    """

    campaign = load_campaign_to_replay(
        db,
        current_user,
        campaign_id,
        "retest",
    )

    try:
        retest_campaign_copy, evaluation, skipped = RetestService.retest(
            db,
            campaign,
            current_user,
            defense_mode,
        )
    except GatewayExecutionError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=str(exc),
        )

    return RetestResponse(
        campaign=retest_campaign_copy,
        evaluation=evaluation,
        skipped_attacks=skipped,
    )


@router.put(
    "/{campaign_id}",
    response_model=CampaignResponse,
)
def update_campaign(
    campaign_id: UUID,
    campaign_data: CampaignUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    campaign = CampaignService.get_by_id(
        db,
        campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_manage_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to modify this campaign",
        )

    if campaign_data.application_id is not None:
        application = ApplicationService.get_by_id(
            db,
            campaign_data.application_id,
        )

        if application is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Application not found",
            )

        if not can_access_application(current_user, application):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not allowed to use this application",
            )

    return CampaignService.update(
        db,
        campaign,
        campaign_data,
    )


@router.delete(
    "/{campaign_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_campaign(
    campaign_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    campaign = CampaignService.get_by_id(
        db,
        campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_manage_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this campaign",
        )

    CampaignService.delete(
        db,
        campaign,
    )