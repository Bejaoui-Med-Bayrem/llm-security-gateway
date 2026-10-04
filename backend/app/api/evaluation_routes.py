from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.schemas.evaluation import EvaluationComparison, EvaluationResponse
from app.services.campaign_service import CampaignService
from app.services.evaluation_service import EvaluationService


router = APIRouter(
    prefix="/evaluations",
    tags=["Evaluations"],
)


def can_access_campaign(current_user, campaign) -> bool:
    return (
        current_user.role == "admin"
        or current_user.id == campaign.created_by
    )


@router.post(
    "/campaign/{campaign_id}",
    response_model=EvaluationResponse,
)
def compute_evaluation(
    campaign_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Compute (or recompute) the campaign's evaluation from the
    executions recorded by the Gateway. Metrics are never
    accepted from the client.
    """

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
            detail="You are not allowed to evaluate this campaign",
        )

    return EvaluationService.refresh_for_campaign(
        db,
        campaign_id,
    )


@router.get(
    "/",
    response_model=list[EvaluationResponse],
)
def get_evaluations(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    evaluations = EvaluationService.get_all(db)

    if current_user.role == "admin":
        return evaluations

    accessible_evaluations = []

    for evaluation in evaluations:
        campaign = CampaignService.get_by_id(
            db,
            evaluation.campaign_id,
        )

        if campaign is None:
            continue

        if campaign.created_by == current_user.id:
            accessible_evaluations.append(evaluation)

    return accessible_evaluations


@router.get(
    "/compare",
    response_model=EvaluationComparison,
)
def compare_evaluations(
    before: UUID,
    after: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Compare two evaluations (ids of evaluations, not of campaigns).
    differences = after - before.
    """

    evaluations = []

    for evaluation_id in (before, after):
        evaluation = EvaluationService.get_by_id(
            db,
            evaluation_id,
        )

        if evaluation is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Evaluation not found",
            )

        campaign = CampaignService.get_by_id(
            db,
            evaluation.campaign_id,
        )

        if campaign is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Campaign not found",
            )

        if not can_access_campaign(current_user, campaign):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not allowed to access this evaluation",
            )

        evaluations.append(evaluation)

    return EvaluationService.compare(
        evaluations[0],
        evaluations[1],
    )


@router.get(
    "/campaign/{campaign_id}",
    response_model=EvaluationResponse,
)
def get_evaluation_by_campaign(
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
            detail="You are not allowed to access this evaluation",
        )

    evaluation = EvaluationService.get_by_campaign(
        db,
        campaign_id,
    )

    if evaluation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation not found",
        )

    return evaluation


@router.get(
    "/{evaluation_id}",
    response_model=EvaluationResponse,
)
def get_evaluation(
    evaluation_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    evaluation = EvaluationService.get_by_id(
        db,
        evaluation_id,
    )

    if evaluation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation not found",
        )

    campaign = CampaignService.get_by_id(
        db,
        evaluation.campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_access_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to access this evaluation",
        )

    return evaluation


@router.delete(
    "/{evaluation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_evaluation(
    evaluation_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    evaluation = EvaluationService.get_by_id(
        db,
        evaluation_id,
    )

    if evaluation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation not found",
        )

    campaign = CampaignService.get_by_id(
        db,
        evaluation.campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if not can_access_campaign(current_user, campaign):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this evaluation",
        )

    EvaluationService.delete(
        db,
        evaluation,
    )