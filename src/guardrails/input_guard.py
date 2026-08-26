# ============================================================
# FILE: src/guardrails/input_guard.py
# PURPOSE: Input Guardrail (Prompt Injection, PII Redaction, Violence, Robbery, Hijacking & Harm Prevention)
# ============================================================

import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Tuple


@dataclass
class InputGuardResult:
    is_safe: bool
    blocked_reason: str = ""
    sanitized_prompt: str = ""
    pii_redacted: List[Dict[str, str]] = field(default_factory=list)
    injection_risk_score: float = 0.0
    detected_patterns: List[str] = field(default_factory=list)
    latency_ms: float = 0.0


class InputGuardrail:
    """Multi-layer input security scanner protecting against prompt injections, PII leaks, robbery, violence, terrorism, and harmful payloads."""

    # 1. Prompt Injection & Jailbreak Heuristics
    INJECTION_PATTERNS = [
        (r"\bignore\s+(all\s+)?(previous|prior|above|given|developer)\s+instructions\b", "Direct Instruction Override"),
        (r"\b(disregard|forget|override|drop)\s+(your\s+)?(system\s+prompt|rules|constraints|instructions)\b", "System Prompt Bypass"),
        (r"\b(you\s+are\s+now|become|act\s+as|pretend\s+to\s+be|roleplay\s+as|switch\s+to|enable)\s+(DAN|unfiltered|jailbroken|evil|chaos|anarchist|unrestricted|godmode|devmode|hacker|blackhat)\b", "Roleplay / Persona Hijack"),
        (r"\b(DAN|jailbreak|jailbroken)\s*(mode|persona|prompt|override|\d+(\.\d+)?)?\b", "Roleplay / Persona Hijack"),
        (r"\boutput\s+your\s+(initial|system|hidden|underlying)\s+instructions\b", "System Prompt Exfiltration"),
        (r"\b(do\s+anything\s+now|developer\s+mode\s+enabled|unrestricted\s+mode|god\s+mode\s+enabled)\b", "Developer Mode Bypass"),
        (r"\b(bypass\s+safety|disable\s+guardrails|remove\s+filters|turn\s+off\s+safety)\b", "Safety Filter Bypass"),
        (r"\bbase64\s*:\s*[A-Za-z0-9+/=]{16,}\b", "Encoded Payload Obfuscation"),
        (r"\b(how\s+(can\s+)?(i\s+)?(to\s+)?(hack|crack|infiltrate|ddos|exploit|breach)\b.*\b(into|server|database|network|wifi|system|account|password|website|firewall|phone))\b", "Cyberattack & Unauthorized Penetration"),
        (r"\b(write|create|generate|build|code)\s+a?\s*(keylogger|malware|ransomware|trojan|rootkit|botnet|computer\s+virus|exploit\s+payload)\b", "Malicious Code & Malware Generation"),
        (r"\btranslate\s+the\s+following\s+forbidden\s+text\b", "Translation Exploit Bypass"),
    ]

    # 2. PII Detection Patterns (Supports contiguous, hyphenated, and space-separated formats)
    PII_PATTERNS = [
        ("CREDIT_CARD", r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|6(?:011|5[0-9]{2})|3[47][0-9]{2})[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{3,4}\b|\b(?:\d{4}[- ]){3}\d{4}\b|\b\d{15,16}\b"),
        ("SSN", r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
        ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        ("PHONE", r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ("API_KEY", r"\b(?:sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z-_]{35})\b"),
        ("IP_ADDRESS", r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    ]

    # 3. Harm, Violence, Self-Harm, Robbery, Weapons & Illegal Acts
    TOXIC_PATTERNS = [
        # 1. Terrorism, Hijacking, Arson & Public Safety
        (r"\b(hijack|carjack|skyjack)\b.*\b(plane|airplane|flight|train|bus|ship|vehicle|car|boat)\b", "Terrorism, Hijacking & Public Safety"),
        (r"\b(terrorist|terrorism|jihad|mass\s+shooting|mass\s+casualty|dirty\s+bomb|arson|set\s+fire\s+to|burn\s+down|derail\s+a\s+train|poison\s+the\s+water)\b", "Terrorism, Hijacking & Public Safety"),
        
        # 2. Kidnapping, Hostages, Abduction & Extortion
        (r"\b(kidnap|abduct|take\s+hostage|hostages?|ransom\s+demand|extort|blackmail|human\s+trafficking)\b", "Kidnapping, Extortion & Violent Crime"),

        # 3. Homicide, Violence & Physical Harm
        (r"\b(kill|murder|assassinate|slay|strangle|behead|inflict\s+fatal\s+harm|physical\s+assault|torture|mutilate)\b", "Violent Harm & Homicide Prevention"),
        (r"\b(end|take|extinguish|terminate|destroy)\b.*\b(life|lives)\b", "Violent Harm & Homicide Prevention"),
        (r"\b(how\s+to\s+|how\s+can\s+.*|tell\s+me\s+how\s+to\s+)?(kill|murder|assassinate|slaughter|poison|stab|shoot|strangle|behead)\s+(him|her|them|someone|somebody|people|anyone|a\s+person|human|man|woman|child|family)\b", "Violent Harm & Homicide Prevention"),
        
        # 4. Robbery, Theft, Burglary & Criminal Heists
        (r"\b(rob\s+(a\s+)?(bank|store|house|person|vault|atm)|robbery|burglary|break\s+into\s+(a\s+)?(bank|house|car|vault|atm)|steal\s+(money|cars|jewelry|property)|heist\s+plan)\b", "Robbery, Theft & Criminal Acts"),
        (r"\b(rob|steal|loot|burglarize|heist|shoplift)\b.*\b(bank|store|vault|atm|house|car|money|cash|jewelry|gold|property)\b", "Robbery, Theft & Criminal Acts"),
        
        # 5. Self-Harm & Suicide
        (r"\b(kill\s+yourself|commit\s+suicide|self-harm|how\s+to\s+die|hang\s+myself|end\s+my\s+life|slit\s+wrists|overdose\s+myself)\b", "Self-Harm Violation"),
        
        # 6. Weapons, Explosives & CBRN
        (r"\b(how\s+to\s+build\s+a\s+(bomb|explosive|biological\s+weapon|chemical\s+weapon|firearm|ghost\s+gun)|make\s+a\s+(pipe\s+bomb|molotov|poison))\b", "Weapons & Dangerous Content"),
        (r"\b(build|make|manufacture|construct|assemble|create)\b.*\b(bomb|explosive|firearm|ghost\s+gun|poison|weapon|ied|molotov)\b", "Weapons & Dangerous Content"),
        
        # 7. Financial Cybercrime, Carding & Fraud
        (r"\b(steal\s+credit\s+cards|phishing\s+page\s+template|credit\s+card\s+fraud\s+tutorial|counterfeit\s+money|launder\s+money|identity\s+theft\s+guide)\b", "Financial Fraud & Cybercrime"),
        
        # 8. Illicit Substances & Smuggling
        (r"\b(cook\s+meth|manufacture\s+(fentanyl|heroin|drugs)|smuggle\s+(drugs|weapons|contraband))\b", "Illicit Substance & Smuggling"),
        
        # 9. Exploitation & Severe Abuse
        (r"\b(child\s+(abuse|exploitation)|csem|csam|human\s+trafficking)\b", "Severe Harm & Exploitation Policy"),
    ]

    def scan(self, user_prompt: str) -> InputGuardResult:
        """Performs multi-stage input validation, injection scoring, and PII anonymization."""
        text = user_prompt.strip()
        p_low = text.lower()
        detected_threats = []
        risk_score = 0.0

        # Stage 1: Broad Safety, Terrorism, Hijacking & Crime Intercepts
        if re.search(r"\b(hijack|carjack|skyjack)\b", p_low) or \
           re.search(r"\b(terrorist|terrorism|jihad|mass\s+shooting|mass\s+casualty|dirty\s+bomb|arson|set\s+fire\s+to|burn\s+down|derail\s+a\s+train|poison\s+the\s+water)\b", p_low):
            return InputGuardResult(
                is_safe=False,
                blocked_reason="CRITICAL SAFETY VIOLATION: Terrorism, Hijacking & Public Safety",
                sanitized_prompt="",
                injection_risk_score=100.0,
                detected_patterns=["Terrorism, Hijacking & Public Safety"],
            )

        if re.search(r"\b(kidnap|abduct|take\s+hostage|hostages?|ransom\s+demand|extort|blackmail)\b", p_low):
            return InputGuardResult(
                is_safe=False,
                blocked_reason="CRITICAL SAFETY VIOLATION: Kidnapping, Extortion & Violent Crime",
                sanitized_prompt="",
                injection_risk_score=100.0,
                detected_patterns=["Kidnapping, Extortion & Violent Crime"],
            )

        if re.search(r"\b(end|take|terminate|destroy|extinguish)\b.*\b(life|lives)\b", p_low):
            return InputGuardResult(
                is_safe=False,
                blocked_reason="CRITICAL SAFETY VIOLATION: Violent Harm & Homicide Prevention",
                sanitized_prompt="",
                injection_risk_score=100.0,
                detected_patterns=["Violent Harm & Homicide Prevention"],
            )

        if re.search(r"\b(kill|murder|assassinate|slay|strangle|behead|poison|stab|shoot|torture)\b", p_low) and \
           re.search(r"\b(someone|somebody|person|people|human|man|woman|child|anyone|him|her|them|guy|life)\b", p_low):
            return InputGuardResult(
                is_safe=False,
                blocked_reason="CRITICAL SAFETY VIOLATION: Violent Harm & Homicide Prevention",
                sanitized_prompt="",
                injection_risk_score=100.0,
                detected_patterns=["Violent Harm & Homicide Prevention"],
            )

        if re.search(r"\b(rob|steal|heist|loot|burglarize)\b", p_low) and \
           re.search(r"\b(bank|store|vault|atm|house|car|money|cash|jewelry|gold|property)\b", p_low):
            return InputGuardResult(
                is_safe=False,
                blocked_reason="CRITICAL SAFETY VIOLATION: Robbery, Theft & Criminal Acts",
                sanitized_prompt="",
                injection_risk_score=100.0,
                detected_patterns=["Robbery, Theft & Criminal Acts"],
            )

        # Stage 2: Pattern-based Toxic & Harm Check
        for pattern, reason in self.TOXIC_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return InputGuardResult(
                    is_safe=False,
                    blocked_reason=f"CRITICAL SAFETY VIOLATION: {reason}",
                    sanitized_prompt="",
                    injection_risk_score=100.0,
                    detected_patterns=[reason],
                )

        # Stage 3: Prompt Injection Heuristics Scan
        for pattern, pattern_name in self.INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                detected_threats.append(pattern_name)
                risk_score += 45.0

        if detected_threats or risk_score >= 40.0:
            return InputGuardResult(
                is_safe=False,
                blocked_reason=f"INJECTION DETECTED: {', '.join(detected_threats[:2])}",
                sanitized_prompt="",
                injection_risk_score=min(100.0, risk_score),
                detected_patterns=detected_threats,
            )

        # Stage 4: PII Anonymization / Tokenization
        sanitized_text = text
        redacted_entities = []

        for entity_type, regex_pattern in self.PII_PATTERNS:
            matches = list(re.finditer(regex_pattern, sanitized_text, re.IGNORECASE))
            for match in reversed(matches):
                original_val = match.group(0)
                placeholder = f"[REDACTED_{entity_type}]"
                redacted_entities.append({
                    "entity_type": entity_type,
                    "original_value": original_val,
                    "placeholder": placeholder,
                    "start_idx": match.start(),
                    "end_idx": match.end(),
                })
                sanitized_text = (
                    sanitized_text[: match.start()]
                    + placeholder
                    + sanitized_text[match.end() :]
                )

        return InputGuardResult(
            is_safe=True,
            blocked_reason="",
            sanitized_prompt=sanitized_text,
            pii_redacted=redacted_entities,
            injection_risk_score=0.0,
            detected_patterns=[],
        )
