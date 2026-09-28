import asyncio
from ..config import get_settings

HONEYPOTS={"cowrie":{"name":"Cowrie SSH/Telnet","protocol":"ssh/telnet","port":"2222/2223","description":"Interactive credential and command deception"},"camera":{"name":"IP Camera","protocol":"http","port":8081,"description":"Camera administration decoy"},"iot-service":{"name":"IoT TCP Device","protocol":"tcp","port":9000,"description":"Line-oriented embedded device decoy"},"mqtt":{"name":"MQTT Broker","protocol":"mqtt","port":1883,"description":"MQTT protocol decoy"},"router":{"name":"Router Admin","protocol":"http","port":8080,"description":"Router administration decoy"}}
class PiManager:
    async def _ssh(self, *arguments: str) -> str:
        cfg=get_settings()
        if not cfg.pi_host: raise RuntimeError("PI_HOST is not configured")
        proc=await asyncio.create_subprocess_exec("ssh","-i",cfg.pi_ssh_key,"-o","BatchMode=yes","-o","IdentitiesOnly=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={cfg.pi_known_hosts}","-o","ConnectTimeout=5",f"{cfg.pi_user}@{cfg.pi_host}","/opt/trapsig/sensor/scripts/manage.sh",*arguments,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        out,err=await proc.communicate()
        if proc.returncode: raise RuntimeError(err.decode().strip() or "Pi action failed")
        return out.decode().strip()

    async def action(self, honeypot_id: str, action: str) -> dict:
        if honeypot_id not in HONEYPOTS: raise ValueError("unknown honeypot")
        if action not in {"start","stop","restart"}: raise ValueError("unsupported action")
        output=await self._ssh(action,honeypot_id)
        return {"honeypot_id":honeypot_id,"action":action,"output":output}

    async def statuses(self) -> dict[str, str]:
        try:
            lines=(await self._ssh("status")).splitlines()
            parsed=dict(line.split("=",1) for line in lines if "=" in line)
            return {name:parsed.get(name,"stopped") for name in HONEYPOTS}
        except RuntimeError:
            return {name:"unreachable" for name in HONEYPOTS}
pi_manager=PiManager()
