from django.test import Client

import pytest


@pytest.fixture
def client():
    return Client()


def test_health_returns_ok(client):
    response = client.get("/health/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_hello_returns_message(client):
    response = client.get("/hello/")
    assert response.status_code == 200
    assert response.json() == {"message": "hello world"}
