from typing import Any

from fastapi.responses import JSONResponse


def api_response(
    data: Any = None, message: str = "", status: str = "success", status_code: int = 200
) -> JSONResponse:
    """Standard API response format."""
    return JSONResponse(
        content={"status": status, "message": message, "data": data},
        status_code=status_code,
    )
