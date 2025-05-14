from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from app.schemas import TransactionResponse


class BlockResponse(BaseModel):
    index: int
    timestamp: int
    hash: str | None
    previous_hash: str | None
    nonce: int
    transactions: list["TransactionResponse"] = []
