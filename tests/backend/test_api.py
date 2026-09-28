from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.elastic import store
from backend.app.services.pi_manager import pi_manager

client=TestClient(app)
async def fake_search(index,query=None,size=100): return []
async def fake_health(): return {"status":"green"}
async def fake_get(index,document_id): return None

def test_health(monkeypatch):
 monkeypatch.setattr(store,"health",fake_health); response=client.get("/health"); assert response.status_code==200 and response.json()["elasticsearch"]=="green"
def test_collection_endpoints(monkeypatch):
 monkeypatch.setattr(store,"search",fake_search)
 for path in ["/events","/sessions","/detections","/experiments"]: assert client.get(path).status_code==200
def test_missing_event(monkeypatch):
 monkeypatch.setattr(store,"get",fake_get); assert client.get("/events/missing").status_code==404
def test_experiment_validation():
 assert client.post("/experiments",json={}).status_code==422
def test_honeypot_validation(monkeypatch):
 async def configured(identifier,action):
  if identifier=="invalid": raise ValueError("unknown honeypot")
  return {"honeypot_id":identifier,"action":action}
 monkeypatch.setattr(pi_manager,"action",configured)
 assert client.post("/honeypots/camera/restart").status_code==200
 assert client.post("/honeypots/invalid/start").status_code==404
