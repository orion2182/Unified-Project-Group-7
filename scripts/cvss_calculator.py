"""CVSS v3.1 Calculator — HackerOne compatible scoring.

Implements CVSS v3.1 specification for vulnerability severity scoring.
Reference: https://www.first.org/cvss/v3.1/specification-document

Usage:
    from scripts.cvss_calculator import CVSSCalculator

    calc = CVSSCalculator()
    score = calc.calculate(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="L",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H"
    )
    print(score)  # 9.8 (Critical)
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict
from datetime import datetime

# CVSS v3.1 Metric Values
METRIC_VALUES = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
}

# Severity ratings
SEVERITY_RATINGS = [
    (0.0, "None"),
    (0.1, "Low"),
    (4.0, "Medium"),
    (7.0, "High"),
    (9.0, "Critical"),
]

# Common CVSS vectors for pentest findings
COMMON_VECTORS = {
    "sql_injection": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xss_stored": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "xss_reflected": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "idor": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "bola": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "auth_bypass": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "privilege_escalation": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "ssrf": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "rce": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "lfi": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "csrf": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "open_redirect": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "info_disclosure": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "rate_limit_bypass": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "mass_assignment": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "session_fixation": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "jwt_weakness": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cors_misconfig": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "missing_auth": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "data_exfiltration": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "denial_of_service": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "improper_input_validation": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
}


@dataclass
class CVSSResult:
    """CVSS v3.1 scoring result."""
    vector_string: str
    base_score: float
    base_severity: str
    exploitability_score: float
    impact_score: float

    # Base metrics
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str

    # Metadata
    vuln_type: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


class CVSSCalculator:
    """CVSS v3.1 Calculator following FIRST.org specification."""

    def __init__(self):
        self.weight = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
            "AC": {"L": 0.77, "H": 0.44},
            "PR": {
                "U": {"N": 0.85, "L": 0.62, "H": 0.27},
                "C": {"N": 0.85, "L": 0.68, "H": 0.5},
            },
            "UI": {"N": 0.85, "R": 0.62},
            "S": {"U": 0, "C": 1},
        }
        self.impact_weight = {"C": 0.56, "I": 0.56, "A": 0.56}

    def _get_severity(self, score: float) -> str:
        """Get severity rating from score."""
        severity = "None"
        for threshold, name in SEVERITY_RATINGS:
            if score >= threshold:
                severity = name
        return severity

    def _round_up(self, value: float) -> float:
        """Round up to 1 decimal place (CVSS spec)."""
        import math
        return math.ceil(value * 10) / 10

    def calculate(
        self,
        attack_vector: str = "N",
        attack_complexity: str = "L",
        privileges_required: str = "N",
        user_interaction: str = "N",
        scope: str = "U",
        confidentiality: str = "H",
        integrity: str = "H",
        availability: str = "H",
        vuln_type: str = "",
    ) -> CVSSResult:
        """Calculate CVSS v3.1 base score.

        Args:
            attack_vector: N=Network, A=Adjacent, L=Local, P=Physical
            attack_complexity: L=Low, H=High
            privileges_required: N=None, L=Low, H=High
            user_interaction: N=None, R=Required
            scope: U=Unchanged, C=Changed
            confidentiality: N=None, L=Low, H=High
            integrity: N=None, L=Low, H=High
            availability: N=None, L=Low, H=High
            vuln_type: Vulnerability type for reference
        """
        # Validate inputs
        for metric, value in [
            ("AV", attack_vector), ("AC", attack_complexity),
            ("PR", privileges_required), ("UI", user_interaction),
            ("S", scope), ("C", confidentiality),
            ("I", integrity), ("A", availability),
        ]:
            if value not in METRIC_VALUES[metric]:
                raise ValueError(f"Invalid {metric} value: {value}")

        # Build vector string
        vector_string = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/"
            f"PR:{privileges_required}/UI:{user_interaction}/S:{scope}/"
            f"C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        # Calculate Exploitability Subscore
        exploitability = (
            8.22 *
            self.weight["AV"][attack_vector] *
            self.weight["AC"][attack_complexity] *
            self.weight["PR"][scope][privileges_required] *
            self.weight["UI"][user_interaction]
        )

        # Calculate Impact Subscore
        impact_subscore = (
            1 - (
                (1 - self.impact_weight["C"] * (1 if confidentiality != "N" else 0)) *
                (1 - self.impact_weight["I"] * (1 if integrity != "N" else 0)) *
                (1 - self.impact_weight["A"] * (1 if availability != "N" else 0))
            )
        )

        # Scope changed?
        if scope == "C":
            impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
        else:
            impact = 6.42 * impact_subscore

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope == "U":
            base_score = self._round_up(min(exploitability + impact, 10))
        else:
            base_score = self._round_up(min(1.08 * (exploitability + impact), 10))

        # Calculate sub-scores
        exploitability_score = self._round_up(exploitability)
        impact_score = self._round_up(impact)

        return CVSSResult(
            vector_string=vector_string,
            base_score=base_score,
            base_severity=self._get_severity(base_score),
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            attack_vector=METRIC_VALUES["AV"][attack_vector],
            attack_complexity=METRIC_VALUES["AC"][attack_complexity],
            privileges_required=METRIC_VALUES["PR"][privileges_required],
            user_interaction=METRIC_VALUES["UI"][user_interaction],
            scope=METRIC_VALUES["S"][scope],
            confidentiality=METRIC_VALUES["C"][confidentiality],
            integrity=METRIC_VALUES["I"][integrity],
            availability=METRIC_VALUES["A"][availability],
            vuln_type=vuln_type,
        )

    def calculate_from_vector(self, vector_string: str, vuln_type: str = "") -> CVSSResult:
        """Calculate CVSS from vector string.

        Args:
            vector_string: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            vuln_type: Vulnerability type
        """
        # Parse vector string
        parts = vector_string.replace("CVSS:3.1/", "").split("/")
        metrics = {}
        for part in parts:
            key, value = part.split(":")
            metrics[key] = value

        return self.calculate(
            attack_vector=metrics.get("AV", "N"),
            attack_complexity=metrics.get("AC", "L"),
            privileges_required=metrics.get("PR", "N"),
            user_interaction=metrics.get("UI", "N"),
            scope=metrics.get("S", "U"),
            confidentiality=metrics.get("C", "N"),
            integrity=metrics.get("I", "N"),
            availability=metrics.get("A", "N"),
            vuln_type=vuln_type,
        )

    def calculate_for_vuln_type(self, vuln_type: str) -> Optional[CVSSResult]:
        """Calculate CVSS for a known vulnerability type.

        Args:
            vuln_type: e.g. "sql_injection", "xss_stored", "idor"
        """
        vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")
        if vuln_type in COMMON_VECTORS:
            return self.calculate_from_vector(COMMON_VECTORS[vuln_type], vuln_type)
        return None

    def get_common_vectors(self) -> Dict[str, str]:
        """Get all common vulnerability vectors."""
        return COMMON_VECTORS.copy()


if __name__ == "__main__":
    import json

    calc = CVSSCalculator()

    # Test common vulnerability types
    print("=" * 70)
    print("CVSS v3.1 Calculator — Common Vulnerability Scores")
    print("=" * 70)

    for vuln_type, vector in sorted(COMMON_VECTORS.items()):
        result = calc.calculate_from_vector(vector, vuln_type)
        print(f"\n{vuln_type.replace('_', ' ').title()}")
        print(f"  Vector: {result.vector_string}")
        print(f"  Score: {result.base_score} ({result.base_severity})")
        print(f"  Exploitability: {result.exploitability_score} | Impact: {result.impact_score}")
