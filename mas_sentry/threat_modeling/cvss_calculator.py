# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Simplified CVSS v3.1 score calculator for MAS vulnerabilities.
https://www.first.org/cvss/specification-document
"""

from dataclasses import dataclass
from typing import Literal

AV = Literal["N", "A", "L", "P"]  # Attack Vector
AC = Literal["L", "H"]  # Attack Complexity
PR = Literal["N", "L", "H"]  # Privileges Required
UI = Literal["N", "R"]  # User Interaction
S = Literal["U", "C"]  # Scope
C = Literal["N", "L", "H"]  # Confidentiality
INTEG = Literal["N", "L", "H"]  # Integrity
A = Literal["N", "L", "H"]  # Availability

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


@dataclass
class CVSSVector:
    attack_vector: AV = "N"
    attack_complexity: AC = "L"
    privileges_required: PR = "N"
    user_interaction: UI = "N"
    scope: S = "U"
    confidentiality: C = "N"
    integrity: INTEG = "N"
    availability: A = "N"


def calculate_cvss(v: CVSSVector) -> float:
    pr_map = _PR_C if v.scope == "C" else _PR_U
    isc = 1 - (1 - _CIA[v.confidentiality]) * (1 - _CIA[v.integrity]) * (1 - _CIA[v.availability])
    impact = 6.42 * isc if v.scope == "U" else 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15

    exploitability = (
        8.22 * _AV[v.attack_vector] * _AC[v.attack_complexity] * pr_map[v.privileges_required] * _UI[v.user_interaction]
    )

    if impact <= 0:
        return 0.0

    raw = min(impact + exploitability, 10) if v.scope == "U" else min(1.08 * (impact + exploitability), 10)

    return round(raw, 1)


# Pre-defined vectors for common MAS attack scenarios
MQTT_ANON_ACCESS = CVSSVector(
    attack_vector="N",
    attack_complexity="L",
    privileges_required="N",
    user_interaction="N",
    scope="C",
    confidentiality="H",
    integrity="H",
    availability="H",
)

MQTT_RETAINED_POISON = CVSSVector(
    attack_vector="N",
    attack_complexity="L",
    privileges_required="N",
    user_interaction="N",
    scope="C",
    confidentiality="L",
    integrity="H",
    availability="H",
)
