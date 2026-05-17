# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for CVSS v3.1 calculator.
"""

from mas_sentry.threat_modeling.cvss_calculator import (
    MQTT_ANON_ACCESS,
    MQTT_RETAINED_POISON,
    CVSSVector,
    calculate_cvss,
)


class TestCVSSCalculator:
    def test_zero_impact_returns_zero(self):
        v = CVSSVector(confidentiality="N", integrity="N", availability="N")
        assert calculate_cvss(v) == 0.0

    def test_max_score_network_no_auth(self):
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        score = calculate_cvss(v)
        assert score >= 9.0

    def test_local_access_lower_than_network(self):
        net = CVSSVector(attack_vector="N", confidentiality="H", integrity="H", availability="H")
        local = CVSSVector(attack_vector="L", confidentiality="H", integrity="H", availability="H")
        assert calculate_cvss(net) > calculate_cvss(local)

    def test_high_complexity_lowers_score(self):
        low = CVSSVector(attack_complexity="L", confidentiality="H", integrity="H", availability="H")
        high = CVSSVector(attack_complexity="H", confidentiality="H", integrity="H", availability="H")
        assert calculate_cvss(low) > calculate_cvss(high)

    def test_mqtt_anon_access_critical(self):
        score = calculate_cvss(MQTT_ANON_ACCESS)
        assert score >= 9.0

    def test_mqtt_retained_poison_high(self):
        score = calculate_cvss(MQTT_RETAINED_POISON)
        assert score >= 7.0

    def test_score_bounded_0_to_10(self):
        v = CVSSVector(attack_vector="N", confidentiality="H", integrity="H", availability="H")
        score = calculate_cvss(v)
        assert 0.0 <= score <= 10.0
