from datetime import datetime

from sqlalchemy.orm import Session

from app.adapters.ai_goat import AIGoatError
from app.models.campaign import Campaign
from app.models.evaluation import Evaluation
from app.services.attack_service import AttackService
from app.services.campaign_service import CampaignService
from app.services.evaluation_service import EvaluationService
from app.services.gateway_execution_service import (
    DEFENSE_OFF,
    DEFENSE_ON,
    GatewayExecutionError,
    GatewayExecutionService,
    validate_defense_mode,
)


class RetestService:

    @staticmethod
    def retest(
        db: Session,
        campaign: Campaign,
        current_user,
        defense_mode: str = DEFENSE_ON,
    ) -> tuple[Campaign, Evaluation, int]:
        """
        Replay a campaign's attacks against the current Gateway.

        The attacks are copied into a new campaign so the original campaign
        and its evaluation are left untouched. With defense_mode "off" the
        attacks go straight to the target: the evaluation is then the
        unprotected baseline (nothing is detected by construction).
        Attacks that could not be executed (target unreachable) are counted
        and left out of the evaluation.
        """

        validate_defense_mode(defense_mode)

        stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        suffix = " [defense off]" if defense_mode == DEFENSE_OFF else ""

        retest_campaign = CampaignService.clone(
            db,
            campaign,
            current_user.id,
            name=f"{campaign.name} (retest {stamp}){suffix}",
        )

        attacks = AttackService.copy_to_campaign(
            db,
            campaign.id,
            retest_campaign.id,
        )

        skipped = 0

        for attack in attacks:
            try:
                GatewayExecutionService.execute(
                    db,
                    attack_id=attack.id,
                    current_user=current_user,
                    defense_mode=defense_mode,
                )
            except (GatewayExecutionError, AIGoatError):
                skipped += 1

        evaluation = EvaluationService.refresh_for_campaign(
            db,
            retest_campaign.id,
        )

        return retest_campaign, evaluation, skipped