import pytest
from attacks.runner.safety import validate_target
def test_accepts_lab_host(): assert validate_target("192.168.50.10","192.168.50.0/24")=="192.168.50.10"
@pytest.mark.parametrize("target",[None,"8.8.8.8","192.168.51.1","192.168.50.0","192.168.50.255"])
def test_rejects_unsafe_target(target):
 with pytest.raises(ValueError): validate_target(target,"192.168.50.0/24")
