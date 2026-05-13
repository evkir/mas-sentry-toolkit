"""
Unit tests for ROS2/DDS threat scenarios.
"""
from mas_sentry.threat_modeling.ros2_threats import ROS2_DDS_THREATS, ROSThreat


class TestROS2Threats:
    def test_catalog_not_empty(self):
        assert len(ROS2_DDS_THREATS) >= 4

    def test_all_have_required_fields(self):
        for t in ROS2_DDS_THREATS:
            assert t.threat_id.startswith("ROS-")
            assert t.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            assert len(t.mitigation) > 10
            assert len(t.description) > 10

    def test_dds_domain_threat_exists(self):
        ids = [t.threat_id for t in ROS2_DDS_THREATS]
        assert "ROS-S-001" in ids

    def test_cmd_vel_injection_exists(self):
        ids = [t.threat_id for t in ROS2_DDS_THREATS]
        assert "ROS-T-001" in ids

    def test_critical_threats_present(self):
        criticals = [t for t in ROS2_DDS_THREATS if t.severity == "CRITICAL"]
        assert len(criticals) >= 1

    def test_components_are_valid(self):
        valid = {"DDS", "ROS2_TOPIC", "ROS2_SERVICE", "ROS2_ACTION"}
        for t in ROS2_DDS_THREATS:
            assert t.component in valid
