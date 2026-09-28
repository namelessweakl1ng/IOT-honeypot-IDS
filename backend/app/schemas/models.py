from datetime import datetime
from pydantic import BaseModel, Field

class ExperimentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    scenario_id: str
    target_honeypots: list[str] = Field(default_factory=list)
    attacker_ip: str
    target_ip: str
    expected_detection: str

class Experiment(ExperimentCreate):
    experiment_id: str
    status: str = "created"
    created_at: datetime
    start_time: datetime | None = None
    end_time: datetime | None = None
    event_ids: list[str] = Field(default_factory=list)
    session_ids: list[str] = Field(default_factory=list)
    detection_ids: list[str] = Field(default_factory=list)
    observed_detection: bool | None = None
    result: str | None = None
