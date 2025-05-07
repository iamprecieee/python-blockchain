import uvicorn
from fastapi import FastAPI

app = FastAPI(title="Blockchain API", description="A simple blockchain implementation")


@app.get("/")
async def root():
    return {"message": "Hello from python-blockchain!"}


if __name__ == "__main__":
    uvicorn.run(app)
