import json
import pytest
from tests.conftest import make_access_token_for_user

def _pretty_json(text: str) -> str:
    try:
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except Exception:
        return text

def assert_status(r, expected: int):
    if r.status_code != expected:
        print("\n========== HTTP DEBUG ==========")
        print("URL:", str(r.request.url))
        print("METHOD:", r.request.method)
        print("REQUEST HEADERS:", dict(r.request.headers))
        # request body (nếu có)
        try:
            content = r.request.content
            if content:
                print("REQUEST BODY:", content.decode("utf-8", errors="replace"))
        except Exception:
            pass

        print("\nSTATUS:", r.status_code)
        print("RESPONSE HEADERS:", dict(r.headers))
        print("RESPONSE TEXT:\n", _pretty_json(r.text))
        print("================================\n")

    assert r.status_code == expected

class _FakeTOTP:
    def __init__(self, secret):
        self.secret = secret

    def provisioning_uri(self, email, issuer_name="MyESI"):
        return f"otpauth://totp/{issuer_name}:{email}?secret={self.secret}"

    def verify(self, code, valid_window=1):
        return code == "123456"


@pytest.mark.asyncio
async def test_me_returns_current_user(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r = await client.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == dev.email
    assert body["role"] == dev.role


@pytest.mark.asyncio
async def test_change_password_wrong_current_password_403(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r = await client.put(
        "/api/users/me/password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "WRONG123456", "new_password": "NewPassw0rd!!"},
    )
    assert_status(r,403)


@pytest.mark.asyncio
async def test_change_password_success(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r = await client.put(
        "/api/users/me/password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "Passw0rd!!", "new_password": "NewPassw0rd!!"},
    )
    assert r.status_code == 200
    assert r.json()["message"] == "Password updated successfully"


@pytest.mark.asyncio
async def test_2fa_setup_creates_secret_and_uri(client, fake_db, monkeypatch):
    # mock pyotp functions
    import app.api.v1.users as users_mod

    monkeypatch.setattr(users_mod.pyotp, "random_base32", lambda: "BASE32SECRET")
    monkeypatch.setattr(users_mod.pyotp.totp, "TOTP", lambda secret: _FakeTOTP(secret))

    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r = await client.get("/api/users/me/2fa/setup", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["secret"] == "BASE32SECRET"
    assert body["otp_auth_url"].startswith("otpauth://totp/")


@pytest.mark.asyncio
async def test_2fa_verify_success_enables_flag(client, fake_db, monkeypatch):
    import app.api.v1.users as users_mod

    # ensure 2fa record exists
    dev = next(u for u in fake_db._users if u.role == "developer")
    await fake_db.seed_two_factor(user_id=dev.id, secret="BASE32SECRET", is_enabled=False)

    # mock TOTP verify
    monkeypatch.setattr(users_mod.pyotp, "TOTP", lambda secret: _FakeTOTP(secret))

    token = make_access_token_for_user(dev)
    r = await client.post(
        "/api/users/me/2fa/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": "123456"},
    )
    assert r.status_code == 200
    assert r.json()["message"] == "Two-factor authentication enabled"
    assert dev.two_factor_enabled is True


@pytest.mark.asyncio
async def test_2fa_verify_invalid_code_403(client, fake_db, monkeypatch):
    import app.api.v1.users as users_mod

    dev = next(u for u in fake_db._users if u.role == "developer")
    await fake_db.seed_two_factor(user_id=dev.id, secret="BASE32SECRET", is_enabled=False)

    monkeypatch.setattr(users_mod.pyotp, "TOTP", lambda secret: _FakeTOTP(secret))

    token = make_access_token_for_user(dev)
    r = await client.post(
        "/api/users/me/2fa/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": "000000"},
    )
    assert r.status_code == 403
