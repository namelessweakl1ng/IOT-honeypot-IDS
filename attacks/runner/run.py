import argparse,json,os,socket,uuid
from datetime import datetime,timezone
from pathlib import Path
import yaml
from .safety import validate_target
PORTS={"ssh":2222,"telnet":2223,"camera":8081,"http":8081,"iot":9000,"mqtt":1883,"router":8080}
def run(scenario_id:str,target:str,source:str="controlled-attacker") -> dict:
    target=validate_target(target,os.environ.get("LAB_SUBNET","")); path=Path(__file__).parents[1]/"scenarios"/f"{scenario_id}.yaml"
    if not path.exists(): raise ValueError("unknown scenario")
    scenario=yaml.safe_load(path.read_text()); start=datetime.now(timezone.utc); completed=[]
    for step in scenario["steps"]:
        service=step["service"]; payload=step.get("payload","").encode().decode("unicode_escape").encode()
        try:
            with socket.create_connection((target,PORTS[service]),timeout=3) as connection: connection.sendall(payload); connection.recv(512)
            completed.append({"service":service,"status":"completed"})
        except OSError as exc: completed.append({"service":service,"status":"connection_failed","error":str(exc)})
    summary={"run_id":"RUN-"+uuid.uuid4().hex[:12],"scenario_id":scenario_id,"start_time":start.isoformat(),"end_time":datetime.now(timezone.utc).isoformat(),"target":target,"source":source,"expected_detection":scenario["expected_detection"],"steps_completed":completed}
    out=Path(__file__).parents[1]/"runs"; out.mkdir(exist_ok=True); (out/f'{summary["run_id"]}.json').write_text(json.dumps(summary,indent=2)); return summary
def main():
    parser=argparse.ArgumentParser(description="Run one bounded TRAPSIG lab scenario"); parser.add_argument("scenario"); parser.add_argument("--target",required=True); args=parser.parse_args(); print(json.dumps(run(args.scenario,args.target),indent=2))
if __name__=="__main__": main()
