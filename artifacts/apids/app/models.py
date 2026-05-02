from pydantic import BaseModel
from typing import Optional, List


class PromptRequest(BaseModel):
    prompt: str
    context: Optional[str] = None


class TrainingRequest(BaseModel):
    dataset_size: Optional[int] = 1000
    test_size: Optional[float] = 0.2
