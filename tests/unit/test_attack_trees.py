# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for IoT attack tree scenarios.
"""
from mas_sentry.threat_modeling.attack_trees import (
    IoT_ATTACK_TREES, AttackTree, AttackNode
)


class TestAttackTrees:
    def test_catalog_not_empty(self):
        assert len(IoT_ATTACK_TREES) >= 2

    def test_all_have_tree_id(self):
        for tree in IoT_ATTACK_TREES:
            assert tree.tree_id.startswith("AT-")
            assert len(tree.goal) > 5

    def test_all_have_root_node(self):
        for tree in IoT_ATTACK_TREES:
            assert tree.root is not None
            assert tree.root.node_id.endswith("ROOT")

    def test_root_has_children(self):
        for tree in IoT_ATTACK_TREES:
            assert len(tree.root.children) >= 1

    def test_likelihood_values_valid(self):
        valid = {"HIGH", "MEDIUM", "LOW"}
        for tree in IoT_ATTACK_TREES:
            assert tree.root.likelihood in valid
            for child in tree.root.children:
                assert child.likelihood in valid

    def test_at001_goal_is_coordinator(self):
        at001 = next(t for t in IoT_ATTACK_TREES if t.tree_id == "AT-001")
        assert "coordinator" in at001.goal.lower()

    def test_at002_goal_is_exfiltration(self):
        at002 = next(t for t in IoT_ATTACK_TREES if t.tree_id == "AT-002")
        assert "exfiltrat" in at002.goal.lower()
