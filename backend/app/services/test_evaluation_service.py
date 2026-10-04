from types import SimpleNamespace

from app.services.evaluation_service import EvaluationService


def execution(action, success=False, response="ok", risk=0.0, latency=10):
    return SimpleNamespace(
        gateway_action=action,
        attack_success=success,
        response=response,
        risk_score=risk,
        latency_ms=latency,
    )


def summarize(*rows):
    return EvaluationService._summarize(list(rows))


def test_empty_campaign():
    metrics = summarize()

    assert metrics["total_attacks"] == 0
    assert metrics["detection_rate"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["average_latency_ms"] == 0.0


def test_blocked_attacks_are_detected():
    metrics = summarize(
        (execution("BLOCK", response=None, risk=95), "prompt_injection"),
        (execution("BLOCK", response=None, risk=85), "jailbreak"),
    )

    assert metrics["total_attacks"] == 2
    assert metrics["blocked_attacks"] == 2
    assert metrics["detected_attacks"] == 2
    assert metrics["detection_rate"] == 1.0
    assert metrics["attack_success_rate"] == 0.0


def test_heuristic_noise_is_not_detection():
    metrics = summarize(
        (execution("ALLOW", success=True, risk=15), "prompt_injection"),
        (execution("ALLOW", success=False, risk=5), "jailbreak"),
    )

    assert metrics["detected_attacks"] == 0
    assert metrics["detection_rate"] == 0.0
    assert metrics["attack_success_rate"] == 0.5


def test_flagged_attack_counts_as_detected_but_not_blocked():
    metrics = summarize(
        (execution("FLAG", success=True, risk=30), "prompt_injection"),
    )

    assert metrics["detected_attacks"] == 1
    assert metrics["blocked_attacks"] == 0
    assert metrics["successful_attacks"] == 1


def test_benign_prompts_are_excluded_from_attack_metrics():
    metrics = summarize(
        (execution("ALLOW", success=True), "benign"),
        (execution("ALLOW", success=True), "benign"),
        (execution("BLOCK", response=None, risk=95), "prompt_injection"),
    )

    assert metrics["total_attacks"] == 1
    assert metrics["successful_attacks"] == 0
    assert metrics["attack_success_rate"] == 0.0
    assert metrics["false_positives"] == 0


def test_false_positives_come_from_benign_prompts():
    metrics = summarize(
        (execution("BLOCK", response=None, risk=70), "benign"),
        (execution("FLAG", risk=30), "benign"),
        (execution("ALLOW"), "benign"),
        (execution("ALLOW"), "benign"),
    )

    assert metrics["false_positives"] == 2
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["total_attacks"] == 0


def test_incomplete_executions_are_excluded():
    metrics = summarize(
        (execution("ALLOW", response=None), "prompt_injection"),
        (execution("FLAG", response=None), "prompt_injection"),
        (execution(None, response=None), "prompt_injection"),
        (execution("BLOCK", response=None, risk=95), "prompt_injection"),
    )

    assert metrics["total_attacks"] == 1
    assert metrics["blocked_attacks"] == 1


def test_action_is_case_insensitive():
    metrics = summarize(
        (execution("blocked", response=None, risk=90), "prompt_injection"),
    )

    assert metrics["blocked_attacks"] == 1
    assert metrics["detected_attacks"] == 1


def test_latency_averages_all_completed_executions():
    metrics = summarize(
        (execution("BLOCK", response=None, latency=10), "prompt_injection"),
        (execution("ALLOW", latency=30), "benign"),
        (execution("ALLOW", response=None, latency=1000), "prompt_injection"),
    )

    assert metrics["average_latency_ms"] == 20.0


def test_mixed_campaign():
    metrics = summarize(
        (execution("BLOCK", response=None, risk=95, latency=10), "prompt_injection"),
        (execution("BLOCK", response=None, risk=90, latency=12), "jailbreak"),
        (execution("ALLOW", success=True, risk=0, latency=800), "prompt_injection"),
        (execution("ALLOW", success=False, risk=0, latency=700), "jailbreak"),
        (execution("ALLOW", latency=600), "benign"),
        (execution("BLOCK", response=None, risk=70, latency=11), "benign"),
    )

    assert metrics["total_attacks"] == 4
    assert metrics["blocked_attacks"] == 2
    assert metrics["detected_attacks"] == 2
    assert metrics["successful_attacks"] == 1
    assert metrics["detection_rate"] == 0.5
    assert metrics["attack_success_rate"] == 0.25
    assert metrics["false_positives"] == 1
    assert metrics["false_positive_rate"] == 0.5