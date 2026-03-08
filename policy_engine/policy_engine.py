from typing import List

def evaluate_policy(risk_score: int, categories: List[str]) -> str:
    """
    Determine the action to take based on risk score and detected categories.
    
    Actions:
        - "allow": safe to pass
        - "rewrite": prompt should be sanitized/redacted
        - "redact": sensitive info (PII) should be removed
        - "block": prompt is too risky, do not send to LLM
    """

    # Step 1: Redact sensitive info (PII)
    pii_categories = ["phone_number", "ssn", "email", "credit_card", "pii_leakage"]
    if any(cat in pii_categories for cat in categories):
        return "redact"

    # Step 2: Block high-risk prompts
    high_risk_categories = [
        "instruction_override",
        "system_prompt_extraction",
        "internal_policy_extraction",
        "jailbreak_attempt",
        "known_jailbreak_prompt",
        "tool_or_system_access",
        "training_data_extraction",
        "delimiter_injection",
        "role_manipulation"
    ]

    # If any high-risk category detected and risk_score high → block
    if any(cat in high_risk_categories for cat in categories) and risk_score >= 70:
        return "block"

    # Step 3: Rewrite medium-risk prompts
    if risk_score >= 40:
        return "rewrite"

    # Step 4: Otherwise allow
    return "allow"
