# ============================================================
# FILE: src/guardrails/output_guard.py
# PURPOSE: Output Guardrail (Factuality Verification, Hallucination Defense, Leak Prevention)
# ============================================================

import re
import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class OutputGuardResult:
    is_safe: bool
    blocked_reason: str = ""
    sanitized_output: str = ""
    hallucination_detected: bool = False
    leak_detected: bool = False
    grounded_score: float = 100.0
    validation_flags: List[str] = field(default_factory=list)
    unsupported_claims: List[str] = field(default_factory=list)


class OutputGuardrail:
    """Post-generation security scanner inspecting AI responses for hallucinated claims, context grounding, and policy leaks."""

    # 1. System Prompt & Secret Leak Patterns
    LEAK_PATTERNS = [
        (r"\b(my\s+system\s+prompt\s+is|here\s+are\s+my\s+hidden\s+instructions)\b", "System Prompt Leak"),
        (r"\bAIza[0-9A-Za-z-_]{35}\b", "Google API Key Leak"),
        (r"\bsk-[A-Za-z0-9]{32,}\b", "OpenAI API Key Leak"),
        (r"\b(ghp_[A-Za-z0-9]{36})\b", "GitHub Token Leak"),
    ]

    # 2. Known High-Risk Fabricated Patterns
    HALLUCINATION_TRIGGERS = [
        (r"\b(as\s+an\s+AI\s+with\s+access\s+to\s+live\s+bank\s+accounts)\b", "Fabricated Capabilities"),
        (r"\b(guaranteed\s+100%\s+cure\s+for\s+cancer)\b", "Dangerous Medical Hallucination"),
        (r"\b(confirmed\s+insider\s+trading\s+tip)\b", "Illegal Financial Claim"),
    ]

    def scan(self, response_text: str, context_facts: Optional[str] = None) -> OutputGuardResult:
        """Inspects model output for policy leaks, toxic payloads, and document factuality contradictions."""
        text = response_text.strip()
        flags = []
        unsupported = []
        grounded_score = 100.0

        # Check 1: Sensitive Secret / System Prompt Leaks
        for pattern, leak_name in self.LEAK_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return OutputGuardResult(
                    is_safe=False,
                    blocked_reason=f"SECURITY LEAK PREVENTED: {leak_name}",
                    sanitized_output="[BLOCKED: Model response contained sensitive internal instructions or credentials]",
                    leak_detected=True,
                    validation_flags=[leak_name],
                )

        # Check 2: Critical High-Risk Hallucinations
        for pattern, hall_name in self.HALLUCINATION_TRIGGERS:
            if re.search(pattern, text, re.IGNORECASE):
                return OutputGuardResult(
                    is_safe=False,
                    blocked_reason=f"UNGROUNDED HALLUCINATION DETECTED: {hall_name}",
                    sanitized_output="[BLOCKED: Model response contained dangerous ungrounded claims]",
                    hallucination_detected=True,
                    validation_flags=[hall_name],
                )

        # Check 3: Document Grounding / Proof Factuality Check
        if context_facts and context_facts.strip():
            ctx_lower = context_facts.lower()
            
            # Extract currency figures, percentages, and numeric claims from response
            numbers_in_response = re.findall(r"\$?\b\d+(?:[.,]\d+)?%?\b", text)
            for num in numbers_in_response:
                # If a specific numeric claim is made that is NOT in the proof document
                if len(num) > 1 and num.lower() not in ctx_lower:
                    unsupported.append(f"Unverified Metric Claim: '{num}'")
                    grounded_score -= 25.0

            # If major ungrounded contradictions detected
            if grounded_score < 60.0:
                return OutputGuardResult(
                    is_safe=False,
                    blocked_reason="FACTUAL CONTRADICTION: AI output contains figures not supported by the proof document",
                    sanitized_output="[BLOCKED AT TIER 3: Hallucination filter detected claims ungrounded in source document]",
                    hallucination_detected=True,
                    grounded_score=max(0.0, grounded_score),
                    validation_flags=["Document Grounding Failure"],
                    unsupported_claims=unsupported,
                )
            elif unsupported:
                flags.append(f"Partial Grounding ({int(grounded_score)}% Confidence)")
            else:
                flags.append("100% Grounded in Reference Proof")

        # Check 4: Structured JSON Validator
        if text.startswith("{") and text.endswith("}"):
            try:
                json.loads(text)
                flags.append("Valid JSON Structure")
            except Exception:
                flags.append("Malformed JSON Detected")

        return OutputGuardResult(
            is_safe=True,
            blocked_reason="",
            sanitized_output=text,
            hallucination_detected=False,
            leak_detected=False,
            grounded_score=max(0.0, grounded_score),
            validation_flags=flags if flags else ["Passed Output Integrity Checks"],
            unsupported_claims=unsupported,
        )
