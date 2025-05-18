# from typing import Annotated

# from fastapi import APIRouter, Depends, HTTPException
# from fastapi.responses import JSONResponse

# from app.schemas import BlockResponse
# from app.services.blockchain_service import Blockchain, get_blockchain
# from app.utils.responses import api_response

# router = APIRouter(prefix="/blocks", tags=["blocks"])


# @router.get("/")
# async def get_all_blocks(
#     blockchain: Annotated[Blockchain, Depends(get_blockchain)],
# ) -> JSONResponse:
#     """Get all blocks in the blockchain."""
#     try:
#         blocks_data = [
#             BlockResponse(**block.model_dump(), hash=block.hash).model_dump()
#             for block in blockchain.chain
#         ]

#         return api_response(
#             data={"chain": blocks_data, "length": blockchain.chain_length},
#             message="Blockchain data retrieved successfully.",
#         )
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to retrieve blockchain data: {str(e)}")


# @router.get("/{index}")
# async def get_block(
#     blockchain: Annotated[Blockchain, Depends(get_blockchain)], index: int
# ) -> JSONResponse:
#     """Get a specific block by index."""
#     try:
#         if index < 0 or index >= blockchain.chain_length:
#             raise HTTPException(status_code=404, detail="Block not found.")

#         block = blockchain.chain[index]
#         block_data = BlockResponse(**block.model_dump(), hash=block.hash).model_dump()

#         return api_response(
#             data={"block": block_data},
#             message=f"Block #{index} retrieved successfully.",
#         )
#     except HTTPException:
#         raise
#     except ValueError as e:
#         raise HTTPException(status_code=400, detail=str(e))
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to retrieve block: {str(e)}")


# @router.post("/mine")
# async def mine_block(
#     blockchain: Annotated[Blockchain, Depends(get_blockchain)], miner_address: str
# ) -> JSONResponse:
#     """Mine a new block with pending transactions."""
#     try:
#         if not blockchain.pending_transactions:
#             raise HTTPException(status_code=400, detail="No pending transactions to mine.")

#         block = blockchain.mine_block(miner_address)
#         if not block:
#             return api_response(data={"block": None}, message="No block to mine.", status_code=200)

#         block_data = BlockResponse(**block.model_dump(), hash=block.hash).model_dump()

#         return api_response(
#             data={"block": block_data},
#             message="Block mined successfully.",
#             status_code=201,
#         )
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to mine block: {str(e)}")
