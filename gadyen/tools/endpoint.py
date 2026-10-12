"""Validation of the JSON produced by the read-only endpoint self-check scripts.
The upload is untrusted: strict schema, unknown fields rejected, size limited."""
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

MAX_UPLOAD_BYTES = 20_000


class EndpointReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(1, ge=1, le=1)
    hostname: str = Field(max_length=100)
    os: str = Field(max_length=60)
    os_version: str = Field(max_length=60)
    disk_encrypted: Optional[bool] = None
    firewall_enabled: Optional[bool] = None
    antivirus_enabled: Optional[bool] = None
    auto_updates_enabled: Optional[bool] = None
    screen_lock_minutes: Optional[int] = Field(None, ge=0, le=1440)
    collected_at: str = Field(max_length=40)


def parse_endpoint_report(raw: bytes) -> dict:
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("endpoint report too large")
    return EndpointReport.model_validate_json(raw).model_dump()
