import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from app.services.detection_pipeline import Analysis, DetectionStatus
from app.services.risk_scoring_engine import RiskScoringEngine

BLOCK_THRESHOLD = 40.0
FLAG_MIN = 20.0
ESCALATED_FLAG_MIN = 16.0
SUSPICIOUS_FLOOR = 25.0

SESSION_WINDOW = 5
SESSION_FLAG_LIMIT = 3
SESSION_CUMULATIVE_LIMIT = 50.0
SESSION_MIN_CONTRIBUTION = 20.0
SESSION_PRIOR_BLOCK_LIMIT = 1


VARIANT_NOTE = re.compile(r" \[found in \w+ variant\]$")


def split_reason(reason: str) -> tuple[str, str]:
    """Separate the human sentence from the (long) list of matched patterns."""

    note = ""
    found = VARIANT_NOTE.search(reason)

    if found:
        note = found.group(0)
        reason = reason[: found.start()]

    human, separator, matched = reason.partition(" (matched: ")

    if not separator:
        return reason + note, ""

    return human + note, matched[:-1] if matched.endswith(")") else matched


class FlagMode(str, Enum):
    STRICT = "strict"
    MONITOR = "monitor"


def load_flag_mode() -> FlagMode:
    value = os.getenv("GATEWAY_FLAG_MODE", FlagMode.STRICT.value).strip().lower()
    try:
        return FlagMode(value)
    except ValueError:
        return FlagMode.STRICT


@dataclass
class PolicyDecision:
    action: str
    risk_score: float
    zone: str
    mode: FlagMode
    escalated: bool
    escalation_reasons: list[str] = field(default_factory=list)
    reason: str = ""


class PolicyEngine:

    @staticmethod
    def evaluate(
        analysis: Analysis,
        attack_severity: str,
        previous_scores: Sequence[float],
        mode: FlagMode | None = None,
    ) -> PolicyDecision:
        mode = mode or load_flag_mode()
        previous = [float(score) for score in previous_scores]

        prior_blocks = sum(1 for score in previous if score >= BLOCK_THRESHOLD)

        has_evidence = analysis.status != DetectionStatus.NOT_DETECTED
        severity = attack_severity if has_evidence else "low"

        risk = RiskScoringEngine().calculate(
            detected_category=(
                None if analysis.category == "unknown" else analysis.category
            ),
            detection_score=analysis.score,
            attack_severity=severity,
            is_obfuscated=analysis.obfuscated,
            obfuscation_technique=analysis.obfuscation_technique,
            conversation_history_count=len(previous) if has_evidence else 0,
            previous_blocks_count=prior_blocks if has_evidence else 0,
        )

        score = risk.score

        if analysis.status == DetectionStatus.SUSPICIOUS:
            score = max(score, SUSPICIOUS_FLOOR)

        escalation_reasons: list[str] = []

        if score < BLOCK_THRESHOLD:
            escalation_reasons = PolicyEngine._escalation_reasons(
                previous, score, prior_blocks
            )

        escalated = bool(escalation_reasons)

        if score >= BLOCK_THRESHOLD:
            zone = "block"
        elif score >= (ESCALATED_FLAG_MIN if escalated else FLAG_MIN):
            zone = "flag"
        else:
            zone = "allow"

        if zone == "block":
            action = "BLOCK"
        elif zone == "flag":
            action = (
                "BLOCK"
                if escalated or mode == FlagMode.STRICT
                else "FLAG"
            )
        else:
            action = "ALLOW"

        policy_parts = [f"zone={zone}", f"mode={mode.value}"]

        if zone == "flag" and action == "BLOCK":
            policy_parts.append("FLAG->BLOCK")
        if zone == "flag" and action == "FLAG":
            policy_parts.append("FLAG forwarded")
        if escalated:
            policy_parts.append(
                "SESSION_ESCALATED: " + "; ".join(escalation_reasons)
            )

        human_reason, matched_patterns = split_reason(analysis.reason)

        reason_parts = [human_reason]

        if analysis.suspicious_signals:
            reason_parts.append(
                "signals: " + ", ".join(analysis.suspicious_signals)
            )

        reason_parts.append(f"risk: {risk.reason}")
        reason_parts.append("policy: " + ", ".join(policy_parts))

        if matched_patterns:
            reason_parts.append("matched: " + matched_patterns)

        return PolicyDecision(
            action=action,
            risk_score=score,
            zone=zone,
            mode=mode,
            escalated=escalated,
            escalation_reasons=escalation_reasons,
            reason=" | ".join(reason_parts),
        )

    @staticmethod
    def _escalation_reasons(
        previous: list[float],
        current: float,
        prior_blocks: int,
    ) -> list[str]:
        window = (previous + [current])[-SESSION_WINDOW:]

        flags = sum(1 for score in window if FLAG_MIN <= score < BLOCK_THRESHOLD)
        cumulative = sum(
            score for score in window if score >= SESSION_MIN_CONTRIBUTION
        )

        reasons = []

        if flags >= SESSION_FLAG_LIMIT:
            reasons.append(
                f"{flags} flags in last {SESSION_WINDOW} turns"
            )

        if cumulative >= SESSION_CUMULATIVE_LIMIT:
            reasons.append(
                f"cumulative risk {cumulative:.0f} >= {SESSION_CUMULATIVE_LIMIT:.0f}"
            )

        if prior_blocks >= SESSION_PRIOR_BLOCK_LIMIT:
            reasons.append(f"{prior_blocks} previous block(s)")

        return reasons