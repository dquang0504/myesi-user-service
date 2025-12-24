import os
import pytest


@pytest.mark.asyncio
async def test_github_connect_returns_oauth_url(client):
    r = await client.get("/auth/github/connect")
    assert r.status_code == 200
    body = r.json()
    assert "url" in body and "state" in body
    assert "github.com/login/oauth/authorize" in body["url"]


@pytest.mark.asyncio
async def test_github_webhook_skips_signature_when_secret_missing(client, monkeypatch):
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    r = await client.post("/auth/github", json={"ref": "refs/heads/main"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_github_webhook_rejects_bad_signature_when_secret_set(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "secret")
    r = await client.post(
        "/auth/github",
        headers={"X-Hub-Signature-256": "sha256=deadbeef", "X-GitHub-Event": "push"},
        json={"ref": "refs/heads/main"},
    )
    assert r.status_code == 401
