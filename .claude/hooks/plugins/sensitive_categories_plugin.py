"""Sensitive categories plugin — medical, biometric, and protected category detection.

Detects GDPR Art.9 special categories of personal data using keyword + context
heuristics. Pure Python, no external dependencies, ~1ms latency.

Entity types: MEDICAL_DATA, BIOMETRIC_DATA, PROTECTED_CATEGORY
"""

import re

from .base import DetectionResult, SensitiveContentPlugin

# --- Medical / health data patterns ---

MEDICAL_ASSIGNMENT_PATTERNS = [
    (r"\bMRN\s*[:=]\s*['\"]?\w+", "Medical record number"),
    (r"\bpatient[_-]?id\s*[:=]\s*['\"]?\w+", "Patient ID assignment"),
    (r"\bdiagnosis\s*[:=]\s*['\"]?\w+", "Diagnosis assignment"),
    (r"\bICD[-.]?10\s*[:=]?\s*[A-Z]\d{2}", "ICD-10 diagnosis code"),
    (r"\b[A-Z]\d{2}\.\d{1,2}\b", "ICD-10 code format"),
    (r"\bmedical[_-]?record\s*[:=]\s*['\"]?\w+", "Medical record assignment"),
    (r"\bprescription[_-]?(id|number|no|rx)\s*[:=]\s*['\"]?\w+", "Prescription ID"),
    (r"\bNPI\s*[:=]\s*['\"]?\d{10}", "National Provider Identifier"),
    (r"\bhealth[_-]?insurance[_-]?id\s*[:=]\s*['\"]?\w+", "Health insurance ID"),
    (r"\bpatient\b.*\b(name|dob|ssn|address)\s*[:=]", "Patient record with PII fields"),
]

MEDICAL_CONTEXT_PATTERNS = [
    (r"\b(patient|diagnosis|prescription|treatment|medication|symptom|prognosis)\b.*\b(name|id|ssn|dob|record)\b", "Medical term with identifier"),
    (r"\b(name|id|employee|person|user)\b.*\b(diagnosis|blood[_-]?type|allergy|medication|condition|disability)\s*[:=]", "Person with medical data"),
]

# --- Biometric data patterns ---

BIOMETRIC_PATTERNS = [
    (r"\bbiometric[_\s-]?(data|id|template|hash|scan|sample|token)\s*[:=]\s*['\"]?\w+", "Biometric data assignment"),
    (r"\b(fingerprint|retina|iris)[_\s-]?(scan|template|hash|data|id|print)\s*[:=]\s*['\"]?\w+", "Fingerprint/retina/iris data"),
    (r"\bface[_\s-]?(id|encoding|embedding|template|recognition|scan)\s*[:=]\s*['\"]?\w+", "Facial recognition data"),
    (r"\bgenetic[_\s-]?(data|sequence|marker|profile|test)\s*[:=]\s*['\"]?\w+", "Genetic data"),
    (r"\bvoice[_\s-]?(print|sample|pattern|id|biometric)\s*[:=]\s*['\"]?\w+", "Voice biometric data"),
    (r"\bpalm[_\s-]?(print|scan|vein)\s*[:=]\s*['\"]?\w+", "Palm print/vein data"),
    (r"\bdna[_\s-]?(sample|sequence|profile|result|test)\s*[:=]\s*['\"]?\w+", "DNA data"),
]

# --- Protected category patterns (GDPR Art.9) ---

PROTECTED_CATEGORY_PATTERNS = [
    (r"\b(race|ethnicity|ethnic[_-]?group)\s*[:=]\s*['\"]?\w+", "Race/ethnicity assignment"),
    (r"\b(religion|religious[_-]?affiliation|faith|denomination)\s*[:=]\s*['\"]?\w+", "Religion assignment"),
    (r"\b(political[_-]?party|political[_-]?affiliation|political[_-]?view)\s*[:=]\s*['\"]?\w+", "Political affiliation assignment"),
    (r"\b(sexual[_-]?orientation|gender[_-]?identity)\s*[:=]\s*['\"]?\w+", "Sexual orientation/gender identity"),
    (r"\b(union[_-]?membership|trade[_-]?union)\s*[:=]\s*['\"]?\w+", "Union membership"),
    (r"\b(disability|disabled|handicap)\s*[:=]\s*['\"]?\w+", "Disability status assignment"),
]

PROTECTED_CONTEXT_PATTERNS = [
    (r"\b(name|person|employee|user|member)\b.*\b(race|ethnicity|religion|political|orientation)\s*[:=]", "Person with protected category data"),
]

# Pre-compile all patterns
_MEDICAL_ASSIGN = [(re.compile(p, re.IGNORECASE), l) for p, l in MEDICAL_ASSIGNMENT_PATTERNS]
_MEDICAL_CONTEXT = [(re.compile(p, re.IGNORECASE), l) for p, l in MEDICAL_CONTEXT_PATTERNS]
_BIOMETRIC = [(re.compile(p, re.IGNORECASE), l) for p, l in BIOMETRIC_PATTERNS]
_PROTECTED = [(re.compile(p, re.IGNORECASE), l) for p, l in PROTECTED_CATEGORY_PATTERNS]
_PROTECTED_CTX = [(re.compile(p, re.IGNORECASE), l) for p, l in PROTECTED_CONTEXT_PATTERNS]


class SensitiveCategoriesPlugin(SensitiveContentPlugin):
    name = "sensitive_categories"
    tier = "EdgeDevice"

    def __init__(self):
        self._categories = ["medical", "biometric", "protected_category"]

    def configure(self, plugin_config: dict) -> None:
        self._categories = plugin_config.get(
            "categories", ["medical", "biometric", "protected_category"]
        )

    def is_available(self) -> bool:
        return True  # Pure Python, no external dependencies

    def _detect_patterns(
        self, text: str, patterns: list, entity_type: str, score: float
    ) -> list[DetectionResult]:
        results = []
        seen = set()
        for pattern, label in patterns:
            for match in pattern.finditer(text):
                if label in seen:
                    continue
                seen.add(label)
                results.append(DetectionResult(
                    entity_type=entity_type,
                    text=match.group(),
                    score=score,
                    start=match.start(),
                    end=match.end(),
                    plugin_name=self.name,
                ))
        return results

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        results = []

        if "medical" in self._categories:
            if not entity_types or "MEDICAL_DATA" in entity_types:
                results.extend(self._detect_patterns(text, _MEDICAL_ASSIGN, "MEDICAL_DATA", 0.90))
                results.extend(self._detect_patterns(text, _MEDICAL_CONTEXT, "MEDICAL_DATA", 0.85))

        if "biometric" in self._categories:
            if not entity_types or "BIOMETRIC_DATA" in entity_types:
                results.extend(self._detect_patterns(text, _BIOMETRIC, "BIOMETRIC_DATA", 0.90))

        if "protected_category" in self._categories:
            if not entity_types or "PROTECTED_CATEGORY" in entity_types:
                results.extend(self._detect_patterns(text, _PROTECTED, "PROTECTED_CATEGORY", 0.90))
                results.extend(self._detect_patterns(text, _PROTECTED_CTX, "PROTECTED_CATEGORY", 0.85))

        return results
