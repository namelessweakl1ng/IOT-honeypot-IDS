# Windows 11 setup (PC1)

The same Docker Compose file works on Windows via Docker Desktop + WSL2.

## 1. Install Docker Desktop

Download from https://www.docker.com/products/docker-desktop/ and install.
Make sure to enable **WSL2 integration** in the installer.

After install: open PowerShell and verify:

```powershell
docker --version
docker compose version
```

## 2. Install Git for Windows

Download from https://git-scm.com/download/win if not already installed.
Use **Git Bash** or **PowerShell** for the rest of these steps.

## 3. Clone + configure

```powershell
git clone <your-repo> iot-honeypot-ids
cd iot-honeypot-ids
copy .env.example .env
notepad .env           # at minimum set ELASTIC_PASSWORD, API_SECRET_KEY
cd dashboard
copy .env.example .env
notepad .env
```

Note: paths in `.env` use forward slashes — Docker Desktop translates them
correctly.

## 4. Start ELK + API

```powershell
cd dashboard
docker compose up -d
docker compose ps
```

Elasticsearch needs ~60s to become healthy. Kibana needs ~90s.

## 5. Verify

```powershell
# Test ES
curl.exe -u elastic:$env:ELASTIC_PASSWORD http://localhost:9200/_cluster/health

# Test API
curl.exe http://localhost:8000/health

# Open Kibana
start http://localhost:5601
```

## PowerShell equivalents of the bash helper scripts

PowerShell wrappers are provided in `scripts/setup/` and `scripts/deployment/`
as `.ps1` files. They invoke the same `docker compose` commands as their
`.sh` counterparts — behaviour is identical.

## WSL2 specifics

If you prefer to run the bash scripts inside WSL2 instead:

```powershell
wsl --install -d Ubuntu
# Reboot
# Inside Ubuntu:
sudo apt update && sudo apt install -y docker.io docker-compose-v2
git clone <your-repo> iot-honeypot-ids
cd iot-honeypot-ids
# proceed as if you were on Linux
```

The Docker daemon from Docker Desktop is shared with WSL2 automatically when
the WSL integration is enabled in Docker Desktop settings.

## Known issues

- **Long path names** — Windows has a 260-char path limit by default. Run
  this once in an elevated PowerShell to lift it:

  ```powershell
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
  ```

- **Line endings** — Git may convert shell scripts to CRLF. Disable this:

  ```powershell
  git config --global core.autocrlf false
  ```

  Re-clone after this change if needed.

- **Resource** — Docker Desktop with WSL2 uses significant RAM. Allocate at
  least 8 GB to WSL2 in `.wslconfig` for comfortable operation.
