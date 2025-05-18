# def test_method_not_allowed(client):
#     """Test error handling for incorrect HTTP method."""
#     response = client.post("/blocks/0")
#     assert response.status_code == 405
#     data = response.json()
#     assert all([data["status"] == "error", "message" in data])
