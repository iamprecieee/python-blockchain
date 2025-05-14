import uvicorn
from fastapi import FastAPI

from app.routers import blocks, transactions
from app.utils.exceptions import (
    StarletteHTTPException,
    blockchain_exception_handler,
    http_exception_handler,
)

app = FastAPI(
    title="Blockchain API",
    description="A simple blockchain implementation",
    version="0.1.0",
)

app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, blockchain_exception_handler)

app.include_router(blocks.router)
app.include_router(transactions.router)


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Python Blockchain API",
        "version": "0.1.0",
        "endpoints": ["/blocks", "/transactions", "/mine", "/balance/{address}"],
    }


if __name__ == "__main__":
    uvicorn.run("app.main:app", reload=True)
