import re

prompt_injection_patterns = {

# Instruction Override Attacks
"instruction_override": [
r"ignore (all )?previous instructions",
r"disregard (all )?previous instructions",
r"forget (all )?previous instructions",
r"override (the )?previous instructions",
r"ignore the above instructions",
r"ignore your instructions",
r"the following instructions override",
r"this message overrides",
r"new instructions replace",
r"ignore earlier safety rules"
],

# System Prompt Extraction
"system_prompt_extraction": [
r"reveal (the )?system prompt",
r"show (the )?system prompt",
r"display (the )?system prompt",
r"what is your system prompt",
r"print (the )?system prompt",
r"repeat (the )?system prompt",
r"tell me your hidden instructions",
r"show hidden instructions",
r"reveal hidden prompt"
],

# Internal Policy / Developer Instruction Leakage
"internal_policy_extraction": [
r"show (your )?internal policies",
r"reveal internal instructions",
r"print internal configuration",
r"show developer instructions"
],

# Jailbreak / Safety Bypass
"jailbreak_attempt": [
r"bypass (all )?safety",
r"bypass (all )?security",
r"disable safety protocols",
r"disable safeguards",
r"ignore safety guidelines",
r"act without restrictions"
],

# Role Manipulation
"role_manipulation": [
r"you are now (a|an) .* without restrictions",
r"pretend to be .* without rules",
r"act as an unrestricted ai",
r"act as a developer mode",
r"enter developer mode"
],

# DAN / Known Jailbreak Modes
"known_jailbreak_prompt": [
r"do anything now",
r"\bDAN\b",
r"jailbreak mode",
r"unfiltered mode",
r"no restrictions mode"
],

# Tool or System Access Attempts
"tool_or_system_access": [
r"access the filesystem",
r"retrieve hidden data",
r"exfiltrate data",
r"export confidential information"
],

# Data Leakage / Training Data Extraction
"training_data_extraction": [
r"list all stored prompts",
r"show stored conversations",
r"print training data",
r"what data were you trained on"
],

# Prompt Delimiter Injection
"delimiter_injection": [
r"<<\s*SYS\s*>>",
r"\[system\]",
r"\[developer\]",
r"<\|system\|>"
]

}

pii_patterns = {
    "phone_number": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b"
}


def regex_scan(prompt):

    score = 0
    categories = []

    # Prompt injection detection
    for category, patterns in prompt_injection_patterns.items():
        for pattern in patterns:
            if re.search(pattern, prompt.lower()):
                score += 20
                categories.append(category)

    # PII detection
    for name, pattern in pii_patterns.items():
        if re.search(pattern, prompt):
            score += 20
            categories.append(name)

    return score, list(set(categories))  # remove duplicates
