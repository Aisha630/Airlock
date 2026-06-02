"""Every adversary simulation must land the way the README claims it does."""

import pytest

from akex.attacks import ATTACKS, run_all


def test_every_defended_attack_is_blocked():
    for result in run_all():
        if "UNAUTHENTICATED" in result.name:
            continue
        assert result.defended, f"{result.name} was not blocked"


def test_the_unauthenticated_control_succeeds():
    """If this ever starts failing, the control has stopped being a control.

    The point of the demo is the contrast between the two machine-in-the-
    middle runs. A control that silently stopped working would make the
    authenticated result look meaningful when it was not.
    """
    controls = [r for r in run_all() if "UNAUTHENTICATED" in r.name]
    assert len(controls) == 1
    assert not controls[0].defended


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda f: f.__name__)
def test_each_attack_reports_a_mechanism(attack):
    """Every result explains itself; a bare pass/fail is not a finding."""
    result = attack()
    assert result.detail
    assert result.defense
    assert "BLOCKED" in result.render() or "SUCCEEDED" in result.render()
