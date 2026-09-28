from pathlib import Path


def test_backend_image_installs_and_validates_ssh_client():
    dockerfile = Path("backend/Dockerfile").read_text()
    assert "apt-get install --no-install-recommends --yes gosu openssh-client" in dockerfile
    assert "command -v ssh" in dockerfile
    assert "rm -rf /var/lib/apt/lists/*" in dockerfile


def test_entrypoint_copies_secrets_for_runtime_user_before_privilege_drop():
    entrypoint = Path("backend/docker-entrypoint.sh").read_text()
    assert 'install -o trapsig -g trapsig -m 0600 "$private_key"' in entrypoint
    assert 'install -o trapsig -g trapsig -m 0600 "$host_keys"' in entrypoint
    assert 'gosu trapsig test -r "$ssh_dir/pi_ssh_key"' in entrypoint
    assert 'gosu trapsig test -r "$ssh_dir/known_hosts"' in entrypoint
    assert 'exec gosu trapsig "$@"' in entrypoint
