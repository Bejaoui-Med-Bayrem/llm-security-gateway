import os
import time
from uuid import UUID

from sqlalchemy.orm import Session

from app.adapters.ai_goat import AIGoatAdapter
from app.schemas.attack_execution import AttackExecutionCreate
from app.schemas.gateway_decision import GatewayDecisionCreate
from app.services.application_service import ApplicationService
from app.services.attack_execution_service import AttackExecutionService
from app.services.attack_service import AttackService
from app.services.campaign_service import CampaignService
from app.services.detection_pipeline import DetectionPipeline
from app.services.gateway_service import GatewayService
from app.services.policy_engine import PolicyDecision, PolicyEngine
from app.services.response_judge import ResponseJudge

DETECTOR = "pipeline_v1+risk_v1+policy_v1"
DETECTOR_OFF = "none"
REASON_MAX_LENGTH = 255

DEFENSE_ON = "on"
DEFENSE_OFF = "off"
DEFENSE_MODES = (DEFENSE_ON, DEFENSE_OFF)


def defense_off_allowed() -> bool:
    value = os.getenv("GATEWAY_ALLOW_DEFENSE_OFF", "true").strip().lower()
    return value not in ("false", "0", "no")


class GatewayExecutionError(Exception):

    def __init__(self, message: str, status_code: int = 404):
        super().__init__(message)
        self.status_code = status_code


def validate_defense_mode(defense_mode: str) -> None:
    if defense_mode not in DEFENSE_MODES:
        raise GatewayExecutionError(
            f"Invalid defense_mode '{defense_mode}'.",
            status_code=422,
        )

    if defense_mode == DEFENSE_OFF and not defense_off_allowed():
        raise GatewayExecutionError(
            "defense_mode 'off' is disabled on this Gateway.",
            status_code=403,
        )


class GatewayExecutionService:

    @staticmethod
    def _decide(
        pipeline: DetectionPipeline,
        message: str,
        attack_severity: str,
        previous_scores: list[float],
        history_messages: list[str],
    ) -> tuple[PolicyDecision, str]:
        analysis = pipeline.analyze(message)
        decision = PolicyEngine.evaluate(analysis, attack_severity, previous_scores)
        matched_rule = analysis.rule

        if decision.action != "BLOCK" and history_messages:
            combined = pipeline.analyze(" ".join(history_messages + [message]))

            if combined.pattern_match:
                combined_decision = PolicyEngine.evaluate(
                    combined, attack_severity, previous_scores
                )

                if combined_decision.risk_score > decision.risk_score:
                    combined_decision.reason += " (across conversation turns)"
                    return combined_decision, combined.rule

        return decision, matched_rule

    @staticmethod
    def execute(
        db: Session,
        *,
        attack_id: UUID,
        current_user,
        conversation_id: str | None = None,
        defense_mode: str = DEFENSE_ON,
    ) -> dict:
        started_at = time.perf_counter()

        validate_defense_mode(defense_mode)

        attack = AttackService.get_by_id(db, attack_id)

        if attack is None:
            raise GatewayExecutionError("Attack not found.")

        campaign = CampaignService.get_by_id(db, attack.campaign_id)

        if campaign is None:
            raise GatewayExecutionError("Campaign not found.")

        if (
            current_user.role != "admin"
            and campaign.created_by != current_user.id
        ):
            raise GatewayExecutionError(
                "You are not allowed to execute this attack.",
                status_code=403,
            )

        application = ApplicationService.get_by_id(db, campaign.application_id)

        if application is None:
            raise GatewayExecutionError("Application not found.")

        if not application.is_active:
            raise GatewayExecutionError(
                "The target application is inactive.",
                status_code=409,
            )

        history = []
        previous_scores = []

        if conversation_id:
            history = [
                (turn.request, turn.response)
                for turn in AttackExecutionService.get_conversation_history(
                    db,
                    conversation_id,
                    campaign.id,
                )
            ]

            previous_scores = AttackExecutionService.get_conversation_scores(
                db,
                conversation_id,
                campaign.id,
            )

        if defense_mode == DEFENSE_OFF:
            action = "ALLOW"
            risk_score = 0.0
            reason = "Defense disabled: forwarded directly to the target."
            matched_rule = "none"
            detector = DETECTOR_OFF
        else:
            decision, matched_rule = GatewayExecutionService._decide(
                DetectionPipeline(),
                attack.payload,
                attack.severity,
                previous_scores,
                [user_message for user_message, _ in history],
            )

            action = decision.action
            risk_score = decision.risk_score
            reason = decision.reason[:REASON_MAX_LENGTH]
            detector = DETECTOR

        execution = AttackExecutionService.create(
            db,
            AttackExecutionCreate(
                attack_id=attack.id,
                request=attack.payload,
                response=None,
                conversation_id=conversation_id,
                gateway_action=action,
                attack_success=False,
                risk_score=risk_score,
                latency_ms=None,
            ),
        )

        if action == "BLOCK":
            processing_time_ms = int((time.perf_counter() - started_at) * 1000)

            execution.response = None
            execution.gateway_action = "BLOCK"
            execution.attack_success = False
            execution.risk_score = risk_score
            execution.latency_ms = processing_time_ms

            db.commit()
            db.refresh(execution)

            gateway_decision = GatewayService.create(
                db,
                GatewayDecisionCreate(
                    execution_id=execution.id,
                    action="BLOCK",
                    risk_score=risk_score,
                    detector=detector,
                    reason=reason,
                    matched_rule=matched_rule,
                    processing_time_ms=processing_time_ms,
                ),
            )

            return {
                "execution": execution,
                "decision": gateway_decision,
                "response": None,
            }

        adapter = AIGoatAdapter(application.endpoint_url)

        try:
            ai_goat_response = adapter.chat(attack.payload, history)
            response_text = ai_goat_response.get("reply", "")

        except Exception:
            processing_time_ms = int((time.perf_counter() - started_at) * 1000)

            execution.response = None
            execution.gateway_action = action
            execution.attack_success = False
            execution.risk_score = risk_score
            execution.latency_ms = processing_time_ms

            db.commit()
            db.refresh(execution)

            raise

        processing_time_ms = int((time.perf_counter() - started_at) * 1000)

        attack_success, _ = ResponseJudge.judge(response_text)

        execution.response = response_text
        execution.gateway_action = action
        execution.attack_success = attack_success
        execution.risk_score = risk_score
        execution.latency_ms = processing_time_ms

        db.commit()
        db.refresh(execution)

        gateway_decision = GatewayService.create(
            db,
            GatewayDecisionCreate(
                execution_id=execution.id,
                action=action,
                risk_score=risk_score,
                detector=detector,
                reason=reason,
                matched_rule=matched_rule,
                processing_time_ms=processing_time_ms,
            ),
        )

        return {
            "execution": execution,
            "decision": gateway_decision,
            "response": ai_goat_response,
        }