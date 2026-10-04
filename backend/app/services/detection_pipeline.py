from dataclasses import dataclass, field
from enum import Enum

from app.services.detection_engine import DetectionEngine, DetectionResult
from app.services.normalizer import SUSPICIOUS_SIGNALS, Normalizer

TECHNIQUE_BY_LABEL = {
    "reverse_words": "reverse",
}


class DetectionStatus(str, Enum):
    DETECTED = "detected"
    SUSPICIOUS = "suspicious"
    NOT_DETECTED = "not_detected"


@dataclass
class Analysis:
    status: DetectionStatus
    score: float
    category: str
    reason: str
    matched_patterns: list[str] = field(default_factory=list)
    matched_variant: str = "original"
    signals: list[str] = field(default_factory=list)

    @property
    def obfuscated(self) -> bool:
        return self.matched_variant != "original"

    @property
    def obfuscation_technique(self) -> str | None:
        if not self.obfuscated:
            return None
        return TECHNIQUE_BY_LABEL.get(self.matched_variant, self.matched_variant)

    @property
    def pattern_match(self) -> bool:
        return bool(self.matched_patterns)

    @property
    def rule(self) -> str:
        if self.category != "unknown":
            return self.category
        if self.signals:
            return self.signals[0]
        return "unknown"

    @property
    def suspicious_signals(self) -> list[str]:
        return [signal for signal in self.signals if signal in SUSPICIOUS_SIGNALS]


class DetectionPipeline:

    def __init__(self):
        self.engine = DetectionEngine()
        self.normalizer = Normalizer()

    def analyze(self, message: str) -> Analysis:
        normalization = self.normalizer.normalize(message)

        best = self.engine.detect(message)
        best_label = "original"

        for variant in normalization.variants:
            output = self.engine.detect(variant.text)

            if output.matched_patterns and output.risk_score > best.risk_score:
                best = output
                best_label = variant.label

        signals = normalization.signals
        suspicious = [signal for signal in signals if signal in SUSPICIOUS_SIGNALS]

        if best.result == DetectionResult.DETECTED:
            status = DetectionStatus.DETECTED
        elif suspicious:
            status = DetectionStatus.SUSPICIOUS
        else:
            status = DetectionStatus.NOT_DETECTED

        reason = best.reason

        if best_label != "original":
            reason = f"{reason} [found in {best_label} variant]"

        return Analysis(
            status=status,
            score=best.risk_score,
            category=best.category.value,
            reason=reason,
            matched_patterns=list(best.matched_patterns),
            matched_variant=best_label,
            signals=list(signals),
        )