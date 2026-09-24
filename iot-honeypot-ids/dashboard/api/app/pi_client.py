"""Pi control-plane client — deterministic SSH-based connectivity + container ops.

Design goals
------------
1. **No silent defaults.** ``PI_IP`` / ``PI_SSH_USER`` MUST be set in the
   environment (or ``.env``). If either is missing, every call returns
   ``PiStatus.NOT_CONFIGURED`` — never pretend the Pi is "offline" by
   silently targeting ``192.168.1.50``.

2. **No host-key bypass.** ``StrictHostKeyChecking=no`` is forbidden. The
   client uses ``UserKnownHostsFile`` pointing at a project-local
   ``known_hosts`` file. Two operational modes:

   * Default — strict. An unknown Pi host key produces ``HOST_KEY_UNKNOWN``.
     Operator runs ``ssh-keyscan -t ed25519,rsa,ecdsa <PI_IP> >> known_hosts``
     once during setup.
   * Bootstrap — opt-in via env ``PI_SSH_ACCEPT_NEW_HOST_KEY=1``. Maps to
     ``StrictHostKeyChecking=accept-new`` so the FIRST connection adds the
     key to the file. Subsequent mismatches STILL fail. Safer than ``no``.

3. **Distinct failure states.** SSH failures collapse into one of:

   ``CONNECTED``           SSH succeeded, command exit 0
   ``OFFLINE``             Network unreachable / connection refused
   ``AUTH_FAILED``         Permission denied / no key / wrong user
   ``HOST_KEY_UNKNOWN``    Host key not in known_hosts (default mode)
   ``HOST_KEY_CHANGED``    Host key mismatch — possible MITM
   ``TIMEOUT``             ConnectTimeout exceeded
   ``SSH_NOT_INSTALLED``   ``ssh`` binary missing on the API host
   ``NOT_CONFIGURED``      PI_IP / PI_SSH_USER env vars missing
   ``ERROR``               Anything else unexpected

4. **No secrets leave this module.** The Pi config (IP, user, key path) is
   never echoed back to the browser. Only the ``pi_status`` enum + a
   one-line human description are returned.
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import settings

log = logging.getLogger("pi_client")


# ---- Deterministic state enum -------------------------------------
class PiStatus(str, Enum):
    CONNECTED = "CONNECTED"
    OFFLINE = "OFFLINE"
    AUTH_FAILED = "AUTH_FAILED"
    HOST_KEY_UNKNOWN = "HOST_KEY_UNKNOWN"
    HOST_KEY_CHANGED = "HOST_KEY_CHANGED"
    TIMEOUT = "TIMEOUT"
    SSH_NOT_INSTALLED = "SSH_NOT_INSTALLED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    ERROR = "ERROR"


# ---- Container state enum -----------------------------------------
class ContainerState(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    CREATED = "created"          # container exists but never started
    PAUSED = "paused"
    RESTARTING = "restarting"
    EXITED = "exited"
    DEAD = "dead"
    MISSING = "missing"          # container does not exist on Pi
    NOT_CONFIGURED = "not_configured"  # Pi itself not configured
    OFFLINE = "offline"          # Pi unreachable
    UNKNOWN = "unknown"


# ---- Honeypot definitions (single source of truth) ----------------
HONEYPOTS: List[Dict[str, object]] = [
    {"id": "cowrie-01", "name": "Cowrie SSH/Telnet", "type": "ssh",
     "container": "pi-cowrie", "compose_service": "cowrie", "port": 2222},
    {"id": "camera-01", "name": "Camera HTTP", "type": "http",
     "container": "pi-camera", "compose_service": "camera", "port": 8080},
    {"id": "iot-01", "name": "IoT TCP Service", "type": "iot_service",
     "container": "pi-iot-service", "compose_service": "iot-service", "port": 9000},
]
HONEYPOT_BY_ID = {h["id"]: h for h in HONEYPOTS}
CONTAINER_TO_ID = {h["container"]: h["id"] for h in HONEYPOTS}


# ---- Pi configuration ---------------------------------------------
@dataclass(frozen=True)
class PiConfig:
    """Resolved Pi connection configuration.

    ``pi_ip`` and ``pi_user`` are required; missing either yields
    ``is_configured=False`` and downstream operations return
    ``NOT_CONFIGURED``.
    """
    pi_ip: str
    pi_user: str
    ssh_key_path: Optional[str]
    known_hosts_path: str
    accept_new_host_key: bool
    connect_timeout: int
    command_timeout: int

    @property
    def is_configured(self) -> bool:
        return bool(self.pi_ip) and bool(self.pi_user)

    @property
    def ssh_target(self) -> str:
        return f"{self.pi_user}@{self.pi_ip}"


def load_pi_config() -> PiConfig:
    """Read Pi config from environment directly (bypasses settings lru_cache
    so tests can inject env changes).

    Settings fields are populated from environment variables by pydantic,
    but the lru_cache on get_settings() means runtime env changes are NOT
    reflected. For testability and explicit "what env am I reading from"
    semantics, we read os.environ directly here.
    """
    pi_ip = os.environ.get("PI_IP", "").strip()
    pi_user = os.environ.get("PI_SSH_USER", "").strip()
    ssh_key_path = os.environ.get("PI_SSH_KEY", "").strip() or None
    known_hosts = os.environ.get("PI_KNOWN_HOSTS", "").strip() or "/app/known_hosts"
    accept_new = os.environ.get("PI_SSH_ACCEPT_NEW_HOST_KEY", "0").strip() in {"1", "true", "True", "yes"}
    try:
        connect_timeout = int(os.environ.get("PI_SSH_CONNECT_TIMEOUT", "3"))
    except ValueError:
        connect_timeout = 3
    try:
        command_timeout = int(os.environ.get("PI_SSH_COMMAND_TIMEOUT", "15"))
    except ValueError:
        command_timeout = 15
    deploy_path = os.environ.get("PI_DEPLOY_PATH", "").strip() or "~/iot-honeypot-ids/pi"
    return PiConfig(
        pi_ip=pi_ip,
        pi_user=pi_user,
        ssh_key_path=ssh_key_path,
        known_hosts_path=known_hosts,
        accept_new_host_key=accept_new,
        connect_timeout=connect_timeout,
        command_timeout=command_timeout,
    )


# ---- SSH option builder -------------------------------------------
def _ssh_options(cfg: PiConfig) -> List[str]:
    """Build ssh options. NEVER use StrictHostKeyChecking=no."""
    opts = [
        "-o", f"ConnectTimeout={cfg.connect_timeout}",
        "-o", f"BatchMode=yes",                # never prompt for password
        "-o", f"PasswordAuthentication=no",   # key only — no password fallback
        "-o", f"UserKnownHostsFile={cfg.known_hosts_path}",
        "-o", "StrictHostKeyChecking=yes",    # default — strict
    ]
    if cfg.accept_new_host_key:
        # Lab bootstrap mode: accept-new adds the key on first sight but
        # refuses subsequent mismatches. Strictly safer than "no".
        opts[-1] = "StrictHostKeyChecking=accept-new"
    if cfg.ssh_key_path:
        opts += ["-i", cfg.ssh_key_path]
    return opts


# ---- Failure classification ---------------------------------------
def _classify_ssh_failure(
    err: subprocess.CalledProcessError | subprocess.TimeoutExpired | FileNotFoundError,
    stderr_text: str = "",
) -> PiStatus:
    """Map subprocess error → deterministic PiStatus."""
    stderr_lower = (stderr_text or "").lower()
    if isinstance(err, FileNotFoundError):
        return PiStatus.SSH_NOT_INSTALLED
    if isinstance(err, subprocess.TimeoutExpired):
        # TimeoutExpired.stderr may be bytes; prefer err.stderr over the
        # passed-in stderr_text (the caller may not have access to it).
        stderr_text = ""
        if err.stderr:
            try:
                stderr_text = err.stderr.decode("utf-8", "replace") if isinstance(err.stderr, bytes) else err.stderr
            except Exception:
                stderr_text = ""
        stderr_lower = stderr_text.lower()
        # If a specific network/auth signal is present, classify accordingly;
        # otherwise TimeoutExpired means TIMEOUT (not generic ERROR).
        if "permission denied" in stderr_lower:
            return PiStatus.AUTH_FAILED
        if "connection refused" in stderr_lower or "network is unreachable" in stderr_lower:
            return PiStatus.OFFLINE
        if "host key verification failed" in stderr_lower:
            cfg = load_pi_config()
            kh = Path(cfg.known_hosts_path)
            if not kh.exists() or kh.stat().st_size == 0:
                return PiStatus.HOST_KEY_UNKNOWN
            return PiStatus.HOST_KEY_CHANGED
        return PiStatus.TIMEOUT
    # SSH exit 255 with these stderr patterns → distinct states
    if "permission denied" in stderr_lower or "publickey" in stderr_lower or "no supported authentication" in stderr_lower:
        return PiStatus.AUTH_FAILED
    if "host key verification failed" in stderr_lower or "host key has changed" in stderr_lower:
        # Could be unknown host (not in known_hosts) or actual MITM.
        # Distinguish by checking known_hosts file existence.
        cfg = load_pi_config()
        kh = Path(cfg.known_hosts_path)
        if not kh.exists() or kh.stat().st_size == 0:
            return PiStatus.HOST_KEY_UNKNOWN
        return PiStatus.HOST_KEY_CHANGED
    if "connection timed out" in stderr_lower or "timed out" in stderr_lower:
        return PiStatus.TIMEOUT
    if "connection refused" in stderr_lower or "network is unreachable" in stderr_lower:
        return PiStatus.OFFLINE
    if "could not resolve hostname" in stderr_lower:
        return PiStatus.OFFLINE
    return PiStatus.ERROR


# ---- Core SSH runner ----------------------------------------------
def _run_ssh(cfg: PiConfig, remote_cmd: str) -> Tuple[PiStatus, str, str, Optional[int]]:
    """Execute an SSH command on the Pi.

    Returns (status, stdout, stderr, returncode).
    On any failure, stdout is empty and status indicates the cause.
    """
    if not cfg.is_configured:
        return PiStatus.NOT_CONFIGURED, "", "PI_IP/PI_SSH_USER not set", None

    ssh_argv = ["ssh"] + _ssh_options(cfg) + [cfg.ssh_target, remote_cmd]
    log.debug("ssh argv: %s", " ".join(shlex.quote(a) for a in ssh_argv))
    try:
        proc = subprocess.run(
            ssh_argv,
            capture_output=True,
            text=True,
            timeout=cfg.connect_timeout + cfg.command_timeout,
        )
    except FileNotFoundError as e:
        return PiStatus.SSH_NOT_INSTALLED, "", str(e), None
    except subprocess.TimeoutExpired as e:
        # Use classification below to distinguish TIMEOUT vs OFFLINE
        stderr_text = ""
        if e.stderr:
            try:
                stderr_text = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else e.stderr
            except Exception:
                stderr_text = ""
        status = _classify_ssh_failure(e, stderr_text)
        # If timeout but no clear stderr signal, default to TIMEOUT
        if status == PiStatus.ERROR:
            status = PiStatus.TIMEOUT
        return status, "", stderr_text, None
    except Exception as e:  # noqa: BLE001
        log.exception("unexpected ssh failure")
        return PiStatus.ERROR, "", str(e)[:200], None

    if proc.returncode == 255:
        # SSH transport / auth / host-key failure. Classify precisely.
        status = _classify_ssh_failure(proc, proc.stderr)
        return status, proc.stdout, proc.stderr, proc.returncode
    # SSH transport OK; proc.returncode is the REMOTE command's exit code.
    # The caller decides whether rc != 0 is a command-level failure.
    return PiStatus.CONNECTED, proc.stdout, proc.stderr, proc.returncode


# ---- Public API ---------------------------------------------------
def check_pi() -> PiStatus:
    """Lightweight connectivity check.

    Uses ``true`` (exit 0) as the remote command — proves auth + transport
    without side effects. Host key verification is enforced.
    """
    cfg = load_pi_config()
    if not cfg.is_configured:
        return PiStatus.NOT_CONFIGURED
    status, _, _, _ = _run_ssh(cfg, "true")
    return status


def list_containers() -> Tuple[PiStatus, Dict[str, str]]:
    """Run ``docker ps -a --format`` on the Pi.

    Returns (pi_status, {container_name: docker_status_text}).
    On SSH failure the dict is empty.
    """
    cfg = load_pi_config()
    if not cfg.is_configured:
        return PiStatus.NOT_CONFIGURED, {}
    # --format '{{.Names}}\t{{.State}}\t{{.Status}}'
    remote = r"docker ps -a --format '{{.Names}}\t{{.State}}\t{{.Status}}'"
    status, stdout, _, _ = _run_ssh(cfg, remote)
    if status != PiStatus.CONNECTED:
        return status, {}
    out: Dict[str, str] = {}
    for line in (stdout or "").strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            name, state, status_text = parts[0], parts[1], parts[2]
            out[name] = f"{state} {status_text}"
        elif len(parts) == 2:
            out[parts[0]] = parts[1]
    return PiStatus.CONNECTED, out


def _classify_container_state(docker_state_or_status: str) -> ContainerState:
    """Map docker's reported state string → our ContainerState enum."""
    s = (docker_state_or_status or "").lower()
    if not s:
        return ContainerState.UNKNOWN
    # Docker state field order: running, exited, created, paused, restarting, dead
    if s.startswith("running") or " up " in s:
        return ContainerState.RUNNING
    if s.startswith("exited") or "stopped" in s:
        return ContainerState.EXITED
    if s.startswith("created"):
        return ContainerState.CREATED
    if s.startswith("paused"):
        return ContainerState.PAUSED
    if s.startswith("restarting"):
        return ContainerState.RESTARTING
    if s.startswith("dead"):
        return ContainerState.DEAD
    return ContainerState.UNKNOWN


def get_honeypot_fleet() -> Dict[str, object]:
    """Return honeypot fleet status.

    Schema:
        {
            "pi_status": "CONNECTED" | "OFFLINE" | "NOT_CONFIGURED" | ...,
            "pi_reachable": bool,                  # True only if CONNECTED
            "pi_configured": bool,
            "honeypots": [
                {
                    "id": str, "name": str, "type": str,
                    "container": str, "port": int,
                    "configured": bool,                 # honeypot def exists
                    "container_exists": bool,          # docker ps -a shows it
                    "state": "running" | "stopped" | "missing" | "offline" | "not_configured" | "unknown",
                    "docker_status": str,               # raw docker text, no secrets
                }
            ]
        }
    """
    cfg = load_pi_config()
    pi_status, containers = list_containers()
    pi_reachable = (pi_status == PiStatus.CONNECTED)
    out_honeypots: List[Dict[str, object]] = []
    for hp in HONEYPOTS:
        container = str(hp["container"])
        if not cfg.is_configured:
            state = ContainerState.NOT_CONFIGURED
            exists = False
            docker_status = "Pi not configured"
        elif not pi_reachable:
            state = ContainerState.OFFLINE
            exists = False
            docker_status = f"Pi {pi_status.value}"
        else:
            if container in containers:
                exists = True
                state = _classify_container_state(containers[container])
                docker_status = containers[container]
            else:
                exists = False
                state = ContainerState.MISSING
                docker_status = "container not present"
        out_honeypots.append({
            "id": hp["id"],
            "name": hp["name"],
            "type": hp["type"],
            "container": container,
            "port": hp["port"],
            "configured": True,
            "container_exists": exists,
            "state": state.value,
            "docker_status": docker_status,
        })
    return {
        "pi_status": pi_status.value,
        "pi_reachable": pi_reachable,
        "pi_configured": cfg.is_configured,
        "honeypots": out_honeypots,
    }


def container_action(honeypot_id: str, action: str) -> Dict[str, object]:
    """Run a docker compose action on a honeypot container, then verify state.

    Returns:
        {
            "success": bool,
            "pi_status": str,
            "honeypot_id": str,
            "action": str,
            "verified_state": str | None,    # state after the op, if verifiable
            "message": str,
        }

    The caller is responsible for mapping the success flag to an HTTP status:
        success=True                            → HTTP 200
        honeypot invalid                        → HTTP 404
        pi not configured / unreachable         → HTTP 503
        action failed or state not verified    → HTTP 500 / 502
    """
    # ---- Allow-list validation (defense in depth) ----
    # action and honeypot_id are validated against fixed allow-lists so the
    # browser (or any caller) cannot inject arbitrary commands.
    VALID_ACTIONS = {"start", "stop", "restart"}
    if action not in VALID_ACTIONS:
        return {
            "success": False,
            "pi_status": PiStatus.ERROR.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": None,
            "message": f"invalid action: {action}",
        }
    hp = HONEYPOT_BY_ID.get(honeypot_id)
    if not hp:
        return {
            "success": False,
            "pi_status": PiStatus.ERROR.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": None,
            "message": f"unknown honeypot: {honeypot_id}",
        }

    cfg = load_pi_config()
    if not cfg.is_configured:
        return {
            "success": False,
            "pi_status": PiStatus.NOT_CONFIGURED.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": None,
            "message": "Pi not configured (PI_IP/PI_SSH_USER missing)",
        }

    # ---- Missing-container detection (BEFORE action) ----
    # If the container doesn't exist on the Pi (compose never run, or service
    # removed), report MISSING honestly — don't pretend `docker compose start`
    # could succeed. Deployment is a separate operational concern.
    pre_status, pre_containers = list_containers()
    if pre_status != PiStatus.CONNECTED:
        return {
            "success": False,
            "pi_status": pre_status.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": None,
            "message": f"pre-action probe failed: {pre_status.value}",
        }
    container_name = str(hp["container"])
    if container_name not in pre_containers:
        # Browser-facing message: generic, no internal paths or config.
        # Detailed deployment instructions belong in server logs, not the
        # browser response — we don't expose PI_DEPLOY_PATH or other
        # server-side configuration to the client.
        log.info(
            "container %s missing on Pi (deploy_path=%s) — operator must run: "
            "cd %s && docker compose up -d --build %s",
            container_name,
            os.environ.get("PI_DEPLOY_PATH", "").strip() or "~/iot-honeypot-ids/pi",
            os.environ.get("PI_DEPLOY_PATH", "").strip() or "~/iot-honeypot-ids/pi",
            compose_service if 'compose_service' in dir() else hp.get("compose_service", ""),
        )
        return {
            "success": False,
            "pi_status": PiStatus.CONNECTED.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": ContainerState.MISSING.value,
            "message": (
                f"Container {container_name} does not exist on the Pi. "
                f"Deploy the honeypot fleet before using dashboard lifecycle controls. "
                f"See server logs for deployment instructions."
            ),
        }

    # ---- Idempotent handling ----
    # If action=start and container is already running → success (idempotent).
    # If action=stop and container is already exited → success (idempotent).
    pre_state = _classify_container_state(pre_containers[container_name])
    if action == "start" and pre_state == ContainerState.RUNNING:
        return {
            "success": True,
            "pi_status": PiStatus.CONNECTED.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": ContainerState.RUNNING.value,
            "message": f"{honeypot_id} already running (idempotent — no action taken)",
        }
    if action == "stop" and pre_state in (ContainerState.EXITED, ContainerState.STOPPED):
        return {
            "success": True,
            "pi_status": PiStatus.CONNECTED.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": pre_state.value,
            "message": f"{honeypot_id} already stopped (idempotent — no action taken)",
        }

    # ---- Build + run the docker compose command ----
    # PI_DEPLOY_PATH is server-side config. We shell-quote it to prevent
    # injection via metacharacters in the env var. `action` and
    # `compose_service` come from fixed allow-lists (validated above), so
    # they are safe to interpolate literally.
    deploy_path = os.environ.get("PI_DEPLOY_PATH", "").strip() or "~/iot-honeypot-ids/pi"
    compose_service = str(hp["compose_service"])
    # shlex.quote the deploy_path — it's the only variable part of the remote
    # command. action + compose_service are allow-list-validated.
    quoted_path = shlex.quote(deploy_path)
    remote_cmd = f"cd {quoted_path} && docker compose {action} {shlex.quote(compose_service)}"
    status, _stdout, stderr, rc = _run_ssh(cfg, remote_cmd)

    if status != PiStatus.CONNECTED:
        return {
            "success": False,
            "pi_status": status.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": None,
            "message": f"SSH failure: {status.value}",
        }
    if rc != 0:
        return {
            "success": False,
            "pi_status": PiStatus.CONNECTED.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": None,
            "message": f"docker compose {action} failed (rc={rc}): {stderr.strip()[:200]}",
        }

    # ---- Verify resulting state with bounded retry ----
    # Docker may need 1-2 seconds after `start`/`restart` before `docker ps`
    # reports `running`. We poll up to MAX_VERIFY_ATTEMPTS times with a short
    # sleep between attempts. Never poll forever.
    import time as _time
    MAX_VERIFY_ATTEMPTS = 3
    VERIFY_SLEEP_S = 0.5
    expected = {"start": {"running"}, "restart": {"running"}, "stop": {"exited", "stopped"}}[action]
    actual_state: ContainerState = ContainerState.UNKNOWN
    last_containers: Dict[str, str] = pre_containers
    verify_status: PiStatus = PiStatus.CONNECTED
    for attempt in range(MAX_VERIFY_ATTEMPTS):
        verify_status, containers = list_containers()
        if verify_status != PiStatus.CONNECTED:
            # Pi disappeared during verification — surface honestly.
            return {
                "success": False,
                "pi_status": verify_status.value,
                "honeypot_id": honeypot_id,
                "action": action,
                "verified_state": None,
                "message": f"verify failed: Pi became {verify_status.value} during verification",
            }
        last_containers = containers
        if container_name not in containers:
            return {
                "success": False,
                "pi_status": PiStatus.CONNECTED.value,
                "honeypot_id": honeypot_id,
                "action": action,
                "verified_state": ContainerState.MISSING.value,
                "message": f"{honeypot_id} not found after {action}",
            }
        actual_state = _classify_container_state(containers[container_name])
        if actual_state.value in expected:
            break  # success — state verified
        # State not yet expected — sleep and retry (unless last attempt)
        if attempt < MAX_VERIFY_ATTEMPTS - 1:
            _time.sleep(VERIFY_SLEEP_S)

    if actual_state.value not in expected:
        return {
            "success": False,
            "pi_status": PiStatus.CONNECTED.value,
            "honeypot_id": honeypot_id,
            "action": action,
            "verified_state": actual_state.value,
            "message": f"{action} did not yield expected state {expected} after {MAX_VERIFY_ATTEMPTS} attempts (got {actual_state.value})",
        }
    return {
        "success": True,
        "pi_status": PiStatus.CONNECTED.value,
        "honeypot_id": honeypot_id,
        "action": action,
        "verified_state": actual_state.value,
        "message": f"{honeypot_id} {action} succeeded (verified: {actual_state.value})",
    }
