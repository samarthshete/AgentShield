from pydantic import BaseModel


class ScannedTarget(BaseModel):
    id: str
    scan_run_id: str
    target_name: str
    target_path: str
    target_kind: str
