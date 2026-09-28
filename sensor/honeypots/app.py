import json,os,socketserver,uuid
from datetime import datetime,timezone

SERVICE=os.getenv("SERVICE","iot-service"); PROTOCOL=os.getenv("PROTOCOL","tcp"); PORT=int(os.getenv("PORT","9000")); LOG=os.getenv("LOG_PATH",f"/logs/{SERVICE}.jsonl")
RESPONSES={"mqtt":b" \x02\x00\x00","iot-service":b"TRAPSIG-IOT READY\r\n","camera":b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=Camera\r\nContent-Length: 0\r\n\r\n","router":b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=Router\r\nContent-Length: 0\r\n\r\n"}
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  data=self.request.recv(4096); now=datetime.now(timezone.utc).isoformat(); text=data.decode(errors="replace")[:1000]
  event={"timestamp":now,"event_id":str(uuid.uuid4()),"category":"web" if SERVICE in {"camera","router"} else "network","type":"connection","action":"request" if data else "connect","outcome":"unknown","source_ip":self.client_address[0],"source_port":self.client_address[1],"destination_port":PORT,"protocol":PROTOCOL,"service":SERVICE,"honeypot_id":SERVICE+"-01","honeypot_type":SERVICE.replace("-","_"),"summary":f"{SERVICE} received {len(data)} bytes","request":{"text":text}}
  os.makedirs(os.path.dirname(LOG),exist_ok=True)
  with open(LOG,"a",encoding="utf-8") as stream: stream.write(json.dumps(event,separators=(",",":"))+"\n")
  self.request.sendall(RESPONSES[SERVICE])
class Server(socketserver.ThreadingTCPServer): allow_reuse_address=True; daemon_threads=True
Server(("0.0.0.0",PORT),Handler).serve_forever()
