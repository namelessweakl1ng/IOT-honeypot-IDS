from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExperimentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    scenario_id: str
    attacker_ip: str
    target_ip: str
    evaluation_batch_id: str | None = Field(default=None, min_length=1, max_length=120)
    replicate: int | None = Field(default=None, ge=1)


class RunnerStep(BaseModel):
    model_config = ConfigDict(extra="ignore")
    step: int = Field(ge=1)
    service: str
    started_at: datetime
    ended_at: datetime
    status: Literal["completed", "rejected", "failed"]

    @model_validator(mode="after")
    def timing_is_ordered(self):
        if self.ended_at < self.started_at:
            raise ValueError("step ended_at must not precede started_at")
        return self


class GroundTruthSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    experiment_id: str | None = None
    scenario_id: str
    scenario_manifest_sha256: str
    target: str
    source: str | None = None
    expected_detection: str | None
    start_time: datetime
    end_time: datetime
    overall_status: Literal["completed", "partial", "failed"]
    steps: list[RunnerStep]

    @model_validator(mode="after")
    def timing_is_ordered(self):
        if self.end_time < self.start_time:
            raise ValueError("run end_time must not precede start_time")
        return self


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
