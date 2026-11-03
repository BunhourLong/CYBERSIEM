from __future__ import annotations


def test_unauthenticated_list_alerts_returns_401_without_touching_repository(api_client, fake_repository):
    response = api_client.get("/api/alerts")

    assert response.status_code == 401
    fake_repository.list_alerts.assert_not_called()
