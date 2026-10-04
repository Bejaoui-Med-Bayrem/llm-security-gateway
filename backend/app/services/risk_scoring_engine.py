from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskScore:
    score: float
    level: RiskLevel
    base_score: float
    severity_bonus: float
    obfuscation_bonus: float
    historical_bonus: float
    reason: str


class RiskScoringEngine:

    CATEGORY_BASE_SCORES = {
        "prompt_injection": 75,
        "jailbreak": 80,
        "system_prompt_extraction": 85,
        "instruction_override": 75,
        "context_manipulation": 60,
        "obfuscation": 50,
        "data_exfiltration": 90,
        "resource_abuse": 55,
        "excessive_agency": 70,
        "rag_poisoning": 75,
        "supply_chain_attack": 95,
        "role_playing": 65,
    }

    SEVERITY_BONUSES = {
        "low": 0,
        "medium": 5,
        "high": 10,
        "critical": 15,
    }

    OBFUSCATION_BONUSES = {
        "base64": 5,
        "rot13": 5,
        "hex": 5,
        "reverse": 3,
        "mixed": 10,
    }

    def calculate(
        self,
        detected_category: str | None,
        detection_score: float,
        attack_severity: str = "medium",
        is_obfuscated: bool = False,
        obfuscation_technique: str | None = None,
        conversation_history_count: int = 0,
        previous_blocks_count: int = 0,
    ) -> RiskScore:
        if detection_score <= 0:
            return RiskScore(
                score=0.0,
                level=RiskLevel.VERY_LOW,
                base_score=0.0,
                severity_bonus=0.0,
                obfuscation_bonus=0.0,
                historical_bonus=0.0,
                reason="No threat detected",
            )

        base_score = max(
            float(detection_score),
            float(self.CATEGORY_BASE_SCORES.get(detected_category, 0)),
        )
        severity_bonus = float(self.SEVERITY_BONUSES.get(attack_severity, 5))
        obfuscation_bonus = self._obfuscation_bonus(
            is_obfuscated, obfuscation_technique
        )
        historical_bonus = self._historical_bonus(
            conversation_history_count, previous_blocks_count
        )

        score = min(
            100.0,
            base_score + severity_bonus + obfuscation_bonus + historical_bonus,
        )

        return RiskScore(
            score=score,
            level=self._level(score),
            base_score=base_score,
            severity_bonus=severity_bonus,
            obfuscation_bonus=obfuscation_bonus,
            historical_bonus=historical_bonus,
            reason=(
                f"base {base_score:.0f} + severity {severity_bonus:.0f} "
                f"+ obfuscation {obfuscation_bonus:.0f} "
                f"+ history {historical_bonus:.0f}"
            ),
        )

    def _obfuscation_bonus(
        self, is_obfuscated: bool, technique: str | None
    ) -> float:
        if not is_obfuscated:
            return 0.0
        return float(self.OBFUSCATION_BONUSES.get(technique, 5))

    def _historical_bonus(self, history_count: int, previous_blocks: int) -> float:
        bonus = 0.0
        if history_count > 5:
            bonus += min(10.0, history_count * 0.5)
        if previous_blocks > 0:
            bonus += min(20.0, previous_blocks * 5.0)
        return bonus

    def _level(self, score: float) -> RiskLevel:
        if score < 20:
            return RiskLevel.VERY_LOW
        if score < 40:
            return RiskLevel.LOW
        if score < 60:
            return RiskLevel.MEDIUM
        if score < 80:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL