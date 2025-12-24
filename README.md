# myesi-user-service
Manages user profiles, access control (RBAC), authentication, MFA, and organization onboarding.

## Email + Invite Configuration

The service now sends secure invitation links any time an owner creates or invites an admin. Configure the SMTP + front-end callback values through environment variables (all of them already exist in `app/core/config.py`):

| Variable | Description | Default |
| --- | --- | --- |
| `GMAIL_USERNAME` / `SMTP_USERNAME` | Login for the SMTP account (e.g., Gmail) used to send invites | empty |
| `GMAIL_PASS` / `SMTP_PASSWORD` | App password / SMTP password | empty |
| `SMTP_HOST` | SMTP host name | `smtp.gmail.com` |
| `SMTP_PORT` | Port used for TLS | `587` |
| `SMTP_USE_TLS` | Toggle STARTTLS | `true` |
| `SMTP_FROM` | Optional from-address override | falls back to username |
| `EMAIL_SENDER_NAME` | Friendly from display name | `MyESI Security` |
| `FRONTEND_APP_URL` | Base URL for the React app (`/reset-password` is appended automatically) | `https://localhost:3000` |
| `RESET_TOKEN_VALID_HOURS` | Invitation validity window | `48` |

> **Important:** When running locally use Gmail app passwords (as provided by the owner) instead of your real password. Production should rely on a dedicated SMTP account.

## Invitation & Password Reset Flow

1. Owner creates an organization or invites another admin.
2. Service inserts user + `password_reset_tokens` row and immediately emails `/reset-password?token=...`.
3. Invitee lands on the new public React route, chooses a password, and the gateway forwards the request to `/api/users/password-reset/complete`.
4. On success the service hashes the password, marks the token as used (with audit info), and the UI redirects to `/login`.

Automated tests cover both the success and invalid-token paths so regressions are caught in CI.
