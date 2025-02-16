from uuid import UUID

from pydantic import BaseModel


class CreatedBy(BaseModel):
    admin_id: UUID


class Rules(BaseModel):
    min_upper_case_letters: int
    min_lower_case_letters: int
    min_digits: int
    min_symbols: int
    min_length: int


class PolicyModel(BaseModel):
    id: UUID
    created_at: float  # UTC timestamp
    created_by: CreatedBy
    rules: Rules
