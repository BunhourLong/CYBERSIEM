from __future__ import annotations


def test_unauthenticated_auth_me_returns_401_without_touching_repository(api_client, fake_repository):
    response = api_client.get("/api/auth/me")

    assert response.status_code == 401
    assert fake_repository.mock_calls == []
