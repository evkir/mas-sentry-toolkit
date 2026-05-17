# SPDX-License-Identifier: AGPL-3.0-or-later
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../scripts"))

from gen_coverage_badge import coverage_color

def test_color_brightgreen():
    assert coverage_color(85) == "brightgreen"

def test_color_yellow():
    assert coverage_color(65) == "yellow"

def test_color_orange():
    assert coverage_color(45) == "orange"

def test_color_red():
    assert coverage_color(20) == "red"
