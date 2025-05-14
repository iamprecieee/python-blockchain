from pydantic import BaseModel


class TransactionCreate(BaseModel):
    sender: str
    recipient: str
    amount: float
    message: str | None = None


class TransactionResponse(BaseModel):
    transaction_id: str
    nonce: int
    sender: str
    recipient: str
    amount: float
    status: str
    timestamp: int
    message: str | None = None
