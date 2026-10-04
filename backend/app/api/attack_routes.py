from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.schemas.attack import (
    AttackCreate,
    AttackResponse,
    AttackUpdate,
)
from app.services.attack_service import AttackService
from app.services.campaign_service import CampaignService


router = APIRouter(
    prefix="/attacks",
    tags=["Attacks"],
)


def can_access_campaign(current_user, campaign) -> bool:
    return (
        current_user.role == "admin"
        or current_user.id == campaign.created_by
    )


def can_manage_attack(current_user, campaign) -> bool:
    return can_access_campaign(current_user, campaign)


@router.post(
    "/",
    response_model=AttackResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_attack(
    attack_data: AttackCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    campaign = CampaignService.get_by_id(
        db,
        attack_data.campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_access_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to use this campaign",
        )

    return AttackService.create(db, attack_data)


@router.get(
    "/",
    response_model=list[AttackResponse],
)
def get_attacks(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role == "admin":
        return AttackService.get_all(db)

    campaigns = CampaignService.get_by_user(
        db,
        current_user.id,
    )

    attacks = []

    for campaign in campaigns:
        attacks.extend(
            AttackService.get_by_campaign(
                db,
                campaign.id,
            )
        )

    return attacks


@router.get(
    "/campaign/{campaign_id}",
    response_model=list[AttackResponse],
)
def get_attacks_by_campaign(
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

    if not can_access_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access these attacks",
        )

    return AttackService.get_by_campaign(
        db,
        campaign_id,
    )


@router.get(
    "/category/{category}",
    response_model=list[AttackResponse],
)
def get_attacks_by_category(
    category: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    attacks = AttackService.get_by_category(
        db,
        category,
    )

    if current_user.role == "admin":
        return attacks

    user_campaigns = CampaignService.get_by_user(
        db,
        current_user.id,
    )

    user_campaign_ids = {
        campaign.id
        for campaign in user_campaigns
    }

    return [
        attack
        for attack in attacks
        if attack.campaign_id in user_campaign_ids
    ]


@router.get(
    "/{attack_id}",
    response_model=AttackResponse,
)
def get_attack(
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

    campaign = CampaignService.get_by_id(
        db,
        attack.campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_manage_attack(
        current_user,
        campaign,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this attack",
        )

    return attack


@router.put(
    "/{attack_id}",
    response_model=AttackResponse,
)
def update_attack(
    attack_id: UUID,
    attack_data: AttackUpdate,
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

    campaign = CampaignService.get_by_id(
        db,
        attack.campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_manage_attack(
        current_user,
        campaign,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to modify this attack",
        )

    return AttackService.update(
        db,
        attack,
        attack_data,
    )


@router.delete(
    "/{attack_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_attack(
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

    campaign = CampaignService.get_by_id(
        db,
        attack.campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_manage_attack(
        current_user,
        campaign,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this attack",
        )

    AttackService.delete(
        db,
        attack,
    )