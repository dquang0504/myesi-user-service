import hashlib
import hmac
import logging
import os
import uuid
import fnmatch
import httpx
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.db.models import User
from app.services.auth import get_current_user
from app.core.config import settings

router = APIRouter(prefix="/auth/github", tags=["GitHub"])
logger = logging.getLogger("github")

# Manifest patterns phổ biến
MANIFEST_PATTERNS = [
    "package.json",
    "go.mod",
    "Gopkg.lock",
    "pom.xml",
    "build.gradle",
    "requirements.txt",
    "pyproject.toml",
    "Cargo.toml",
    "packages.config",
    "*.csproj",
    "Gemfile",
    "Gemfile.lock",
]


# -------------------------
# 1. Connect GitHub (init OAuth)
# -------------------------
@router.get("/connect")
async def github_connect():
    state = str(uuid.uuid4())  # chống CSRF
    oauth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.GITHUB_CLIENT_ID}"
        f"&redirect_uri={settings.GITHUB_OAUTH_REDIRECT_URI}"
        f"&scope=repo"
        f"&state={state}"
    )
    return {"url": oauth_url, "state": state}


# -------------------------
# 2. Callback - lưu token vào DB
# -------------------------
@router.get("/callback")
async def github_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):

    print("⚙️ GitHub callback start", code, state, request.headers.get("Authorization"))
    async with httpx.AsyncClient(verify=False) as client:
        res = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_OAUTH_REDIRECT_URI,
                "state": state,
            },
        )
        token_data = res.json()
        access_token = token_data.get("access_token")
        if not access_token:
            print("GitHub token exchange failed:", token_data)
            return {"message": "GitHub OAuth temporary failure, please retry"}

        # Lưu token vào user
        current_user.github_token = access_token
        print("Here is accessToken: ", access_token)
        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)

    return {"message": "GitHub connected successfully"}


# -------------------------
# 3. Lấy repo và quét manifest
# -------------------------
async def scan_manifests(
    owner: str, repo: str, token: str, path: str = ""
) -> list[str]:
    headers = {"Authorization": f"token {token}"}
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    async with httpx.AsyncClient() as client:
        res = await client.get(url, headers=headers)
        if res.status_code != 200:
            return []
        items = res.json()

    manifests = []
    for item in items:
        if item["type"] == "file":
            for pattern in MANIFEST_PATTERNS:
                if fnmatch.fnmatch(item["name"], pattern):
                    manifests.append(item["path"])
        elif item["type"] == "dir":
            # recursive scan folder
            manifests += await scan_manifests(owner, repo, token, path=item["path"])
    return manifests


@router.get("/repos")
async def github_repos(current_user: User = Depends(get_current_user)):
    if not current_user.github_token:
        raise HTTPException(status_code=403, detail="GitHub not connected")

    headers = {"Authorization": f"token {current_user.github_token}"}

    async with httpx.AsyncClient() as client:
        # Step 1: lấy danh sách repo
        try:
            res = await client.get(
                "https://api.github.com/user/repos",
                headers=headers,
                params={"per_page": 100, "affiliation": "owner,collaborator"},
            )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502, detail=f"GitHub API request failed: {exc}"
            )

        if res.status_code in (401, 403):
            raise HTTPException(
                status_code=403,
                detail="GitHub access token invalid or expired. Please reconnect GitHub.",
            )
        if res.status_code != 200:
            raise HTTPException(
                status_code=res.status_code,
                detail=f"Failed to fetch GitHub repositories: {res.text}",
            )

        repos = res.json()
        results = []

        # Step 2: gọi API languages cho từng repo
        for repo in repos:
            langs = []

            try:
                langs_res = await client.get(repo["languages_url"], headers=headers)
                if langs_res.status_code == 200:
                    raw = langs_res.json()
                    langs = sorted(raw.keys(), key=lambda lang: raw[lang], reverse=True)
            except Exception as e:
                print(f"[WARN] Failed to fetch languages for {repo['name']}: {e}")

            results.append(
                {
                    "id": repo["id"],
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "html_url": repo["html_url"],
                    "visibility": repo.get("visibility", "public"),
                    "default_branch": repo.get("default_branch", "main"),
                    "languages": langs,
                    "owner": repo["owner"]["login"],
                    "organization_id": current_user.organization_id,
                }
            )

    # Step 3: trả kết quả
    return results


@router.get("/status")
async def github_status(current_user: User = Depends(get_current_user)):
    """Check if current user connected GitHub."""
    return {"connected": bool(current_user.github_token)}


@router.post("")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
):
    raw_body = await request.body()

    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if secret:
        if not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Missing or invalid signature")

        expected = (
            "sha256="
            + hmac.new(
                secret.encode("utf-8"),
                raw_body,
                hashlib.sha256,
            ).hexdigest()
        )

        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()

    if x_github_event == "push":
        repo = payload.get("repository", {}).get("full_name", "unknown/repo")
        ref = payload.get("ref", "")
        branch = (
            ref.split("/", 2)[-1]
            if ref.startswith("refs/heads/")
            else (ref or "unknown")
        )
        commits = payload.get("commits", [])
        pusher = (
            payload.get("pusher", {}).get("name")
            or payload.get("sender", {}).get("login")
            or "unknown"
        )
        head_commit_sha = payload.get("after")

        logger.info(
            "GitHub push detected: repo=%s branch=%s commits=%d pusher=%s head_sha=%s",
            repo,
            branch,
            len(commits),
            pusher,
            head_commit_sha,
        )
    else:
        logger.info("Received GitHub event: %s", x_github_event)

    return {"ok": True}
