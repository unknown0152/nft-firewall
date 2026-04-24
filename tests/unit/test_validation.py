import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from utils.validation import validate_block_target, validate_port, validate_trusted_target


def test_block_target_rejects_default_route():
    result = validate_block_target("0.0.0.0/0")
    assert not result.ok


def test_block_target_rejects_never_block_overlap():
    result = validate_block_target("203.0.113.10", never_block=["203.0.113.0/24"])
    assert not result.ok


def test_block_target_accepts_public_cidr():
    result = validate_block_target("198.51.100.0/24")
    assert result.ok
    assert result.value == "198.51.100.0/24"


def test_trusted_target_rejects_private_range():
    result = validate_trusted_target("192.168.1.50")
    assert not result.ok


def test_validate_port_bounds():
    assert validate_port("443") == 443
