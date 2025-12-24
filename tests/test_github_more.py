import pytest
from tests.conftest import make_access_token_for_user


class FakeHTTPXResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text

    def json(self):
        return self._json


class FakeAsyncClient:
    """
    Fake for httpx.AsyncClient used inside github.py
    Must support: async with ..., get(), post()
    """
    def __init__(self, *args, **kwargs):
        self._routes = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def set_route(self, method: str, url: str, response: FakeHTTPXResponse):
        self._routes[(method.upper(), url)] = response

    async def post(self, url, headers=None, data=None, json=None, params=None):
        return self._routes.get(("POST", url), FakeHTTPXResponse(status_code=500, json_data={}, text="no route"))

    async def get(self, url, headers=None, params=None):
        return self._routes.get(("GET", url), FakeHTTPXResponse(status_code=500, json_data={}, text="no route"))


@pytest.mark.asyncio
async def test_github_status_connected_false_then_true(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r1 = await client.get("/auth/github/status", headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200
    assert r1.json()["connected"] is False

    dev.github_token = "gho_test"
    r2 = await client.get("/auth/github/status", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    assert r2.json()["connected"] is True


@pytest.mark.asyncio
async def test_github_repos_requires_connected_token(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r = await client.get("/auth/github/repos", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_github_repos_success_mocks_httpx(client, fake_db, monkeypatch):
    import app.api.v1.github as gh_mod

    dev = next(u for u in fake_db._users if u.role == "developer")
    dev.github_token = "gho_test"
    token = make_access_token_for_user(dev)

    fake_client = FakeAsyncClient()
    # /user/repos response
    fake_client.set_route(
        "GET",
        "https://api.github.com/user/repos",
        FakeHTTPXResponse(
            status_code=200,
            json_data=[
                {
                    "id": 1,
                    "name": "repo1",
                    "full_name": "me/repo1",
                    "html_url": "https://github.com/me/repo1",
                    "visibility": "private",
                    "default_branch": "main",
                    "languages_url": "https://api.github.com/repos/me/repo1/languages",
                    "owner": {"login": "me"},
                }
            ],
        ),
    )
    # languages_url response
    fake_client.set_route(
        "GET",
        "https://api.github.com/repos/me/repo1/languages",
        FakeHTTPXResponse(status_code=200, json_data={"Python": 1000, "Go": 10}),
    )

    # monkeypatch httpx.AsyncClient to return our fake (note: github.py creates a new client each time)
    monkeypatch.setattr(gh_mod.httpx, "AsyncClient", lambda *a, **kw: fake_client)

    r = await client.get("/auth/github/repos", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert body[0]["name"] == "repo1"
    assert body[0]["languages"][0] == "Python"


@pytest.mark.asyncio
async def test_github_callback_exchanges_token_and_persists_to_user(client, fake_db, monkeypatch):
    import app.api.v1.github as gh_mod

    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    fake_client = FakeAsyncClient()
    fake_client.set_route(
        "POST",
        "https://github.com/login/oauth/access_token",
        FakeHTTPXResponse(status_code=200, json_data={"access_token": "gho_newtoken"}),
    )
    monkeypatch.setattr(gh_mod.httpx, "AsyncClient", lambda *a, **kw: fake_client)

    r = await client.get(
        "/auth/github/callback?code=abc&state=xyz",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["message"] == "GitHub connected successfully"
    assert dev.github_token == "gho_newtoken"


@pytest.mark.asyncio
async def test_github_callback_handles_missing_access_token_gracefully(client, fake_db, monkeypatch):
    import app.api.v1.github as gh_mod

    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    fake_client = FakeAsyncClient()
    fake_client.set_route(
        "POST",
        "https://github.com/login/oauth/access_token",
        FakeHTTPXResponse(status_code=200, json_data={"error": "bad_verification_code"}),
    )
    monkeypatch.setattr(gh_mod.httpx, "AsyncClient", lambda *a, **kw: fake_client)

    r = await client.get(
        "/auth/github/callback?code=bad&state=xyz",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert "temporary failure" in r.json()["message"].lower()
