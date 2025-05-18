# from typing import Annotated

# from fastapi import APIRouter, Depends, HTTPException
# from fastapi.responses import JSONResponse

# from app.models import *
# from app.schemas import TransactionCreate, TransactionResponse
# from app.services.blockchain_service import Blockchain, get_blockchain
# from app.utils.responses import api_response

# router = APIRouter(prefix="/transactions", tags=["transactions"])


# @router.get("/")
# async def get_pending_transactions(
#     blockchain: Annotated[Blockchain, Depends(get_blockchain)],
# ) -> JSONResponse:
#     """Get all pending transactions."""
#     try:
#         transactions_data = [
#             TransactionResponse(**transaction.model_dump()).model_dump()
#             for transaction in blockchain.pending_transactions
#         ]

#         return api_response(
#             data={"pending_transactions": transactions_data},
#             message=f"Retrieved {len(transactions_data)} pending transactions.",
#         )
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(
#             status_code=500, detail=f"Failed to retrieve pending transactions: {str(e)}"
#         )


# @router.post("/")
# async def create_transaction(
#     blockchain: Annotated[Blockchain, Depends(get_blockchain)],
#     transaction: TransactionCreate,
# ) -> JSONResponse:
#     """Create a new transaction."""
#     try:
#         new_transaction = Transaction(
#             sender=transaction.sender,
#             recipient=transaction.recipient,
#             amount=transaction.amount,
#             message=transaction.message,
#         )
#         success = blockchain.add_transaction(new_transaction)
#         if not success:
#             raise HTTPException(status_code=400, detail="Invalid transaction.")

#         transaction_data = TransactionResponse(**new_transaction.model_dump()).model_dump()

#         return api_response(
#             data={"transaction": transaction_data},
#             message="Transaction added successfully.",
#             status_code=201,
#         )
#     except HTTPException:
#         raise
#     except ValueError as e:
#         raise HTTPException(status_code=400, detail=str(e))
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to create transaction: {str(e)}")


# @router.get("/balance/{address}")
# async def get_balance(
#     blockchain: Annotated[Blockchain, Depends(get_blockchain)], address: str
# ) -> JSONResponse:
#     """Get the balance for an address."""
#     try:
#         balance = blockchain.get_balance(address)

#         return api_response(
#             data={"address": address, "balance": balance},
#             message=f"Balance retrieved successfully for {address}.",
#         )
#     except HTTPException:
#         raise
#     except ValueError as e:
#         raise HTTPException(status_code=400, detail=str(e))
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to retrieve balance: {str(e)}")
