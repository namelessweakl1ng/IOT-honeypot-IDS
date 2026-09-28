from pathlib import Path


def test_frontend_uses_internal_backend_url_and_safe_proxy():
    compose = Path("docker-compose.yml").read_text()
    client = Path("frontend/src/lib/api.ts").read_text()
    proxy = Path("frontend/src/app/api/[...path]/route.ts").read_text()
    assert "API_URL: \"http://backend:8000\"" in compose
    assert 'process.env.API_URL ?? "http://backend:8000"' in client
    assert 'path.join("/")' in proxy
    assert "NEXT_PUBLIC" + "_API_URL" not in compose


def test_private_key_is_mounted_read_only_and_ignored():
    compose = Path("docker-compose.yml").read_text()
    assert "/run/trapsig-secrets/pi_ssh_key:ro,Z" in compose
    assert "/run/trapsig-secrets/known_hosts:ro,Z" in compose
    assert "PI_KNOWN_HOSTS: /home/trapsig/.ssh/known_hosts" in compose
    assert "secrets/" in Path(".gitignore").read_text()
