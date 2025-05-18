# from fastapi import HTTPException
# from fastapi.responses import JSONResponse
# from starlette.exceptions import HTTPException as StarletteHTTPException
# from starlette.requests import Request


# async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
#     """Global exception handler for HTTP exceptions."""
#     return JSONResponse(
#         status_code=exc.status_code,
#         content={"status": "error", "message": exc.detail, "data": None},
#     )


# async def blockchain_exception_handler(request: Request, exc: Exception) -> JSONResponse:
#     """Global exception handler for blockchain-specific exceptions."""
#     return JSONResponse(
#         status_code=500, content={"status": "error", "message": str(exc), "data": None}
#     )
