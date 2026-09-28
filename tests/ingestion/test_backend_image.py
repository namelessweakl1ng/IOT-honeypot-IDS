from pathlib import Path


def test_backend_image_installs_and_validates_ssh_client():
    dockerfile = Path("backend/Dockerfile").read_text()
    assert "apt-get install --no-install-recommends --yes openssh-client" in dockerfile
    assert "command -v ssh" in dockerfile
    assert "rm -rf /var/lib/apt/lists/*" in dockerfile
