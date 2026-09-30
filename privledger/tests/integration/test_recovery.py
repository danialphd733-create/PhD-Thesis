"""Timing checks only: these tests never mutate infrastructure."""
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("ipfs_recovery", Path(__file__).resolve().parents[2] / "scripts/ipfs_recovery.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def clock(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


def test_wait_requires_predicate_and_reports_elapsed():
    timer = FakeClock()
    elapsed = module.wait_until(lambda: timer.now >= 0.3, 1, clock=timer.clock, sleep=timer.sleep)
    assert elapsed == pytest.approx(0.3)


def test_wait_timeout_is_not_success():
    timer = FakeClock()
    with pytest.raises(TimeoutError):
        module.wait_until(lambda: False, 0.25, clock=timer.clock, sleep=timer.sleep)
    assert timer.now == pytest.approx(0.25)


def test_wait_process_failure_propagates():
    timer = FakeClock()
    def process_dead():
        raise RuntimeError("Replacement exited")
    with pytest.raises(RuntimeError, match="Replacement exited"):
        module.wait_until(process_dead, 1, clock=timer.clock, sleep=timer.sleep)
