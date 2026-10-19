# AI Safety Summit — Delegate Sign-In & Entry Pass System

A lightweight event registration and check-in app built with FastAPI, SQLite, and
client-side QR generation/scanning.

## Setup

1. Install Python 3.10 or newer and the packages in `requirements.txt`:
   `python -m pip install -r requirements.txt`
2. Copy `.env.example` to `.env`.
3. Generate two different random values with
   `python -c "import secrets; print(secrets.token_urlsafe(32))"` and set
   `CODE_SECRET` and `STAFF_KEY` in `.env`. Both must be at least 32 and 24
   characters respectively. Do not share or commit `.env`.
4. Create a **named Cloudflare Tunnel** for a hostname on a domain in your
   Cloudflare account. Configure its ingress to forward that hostname to
   `http://127.0.0.1:8000`, followed by a `http_status:404` catch-all. The
   tunnel's local configuration file should be
   `%USERPROFILE%\.cloudflared\config.yml`; `run.bat` starts this named tunnel.
   Quick Tunnels (`trycloudflare.com`) are intentionally not used because their
   changing hostnames cannot provide a stable Access policy.
   A typical local configuration is:

   ```yaml
   tunnel: <TUNNEL-UUID>
   credentials-file: C:\Users\<YOUR-USER>\.cloudflared\<TUNNEL-UUID>.json
   ingress:
     - hostname: checkin.example.com
       service: http://127.0.0.1:8000
     - service: http_status:404
   ```

   Replace the example hostname, tunnel ID, and credentials path with the
   values created for your Cloudflare account.
5. In Cloudflare Zero Trust, create a **Self-hosted** Access application for
   your stable hostname and protect `/scan` plus these exact staff API paths:
   `/api/attendees`, `/api/checkin`, `/api/checkin_by_id`, `/api/stats`,
   `/api/offline_roster`, and `/api/sync_checkins`. Add an Allow policy limited
   to your event volunteers. Do not protect `/badge` or `/api/resolve` and
   `/api/generate`; delegates need those routes to use their private invitation
   links. Copy the Access team's domain (for example
   `your-team.cloudflareaccess.com`) and the application's **Audience (AUD)
   tag** into `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` in `.env`.
6. Put the registration roster in `delegates.csv`. Accepted headers are either
   `name,email` or `Full Name,Email Address`. Set `BASE_URL` in `.env` to the
   public tunnel hostname before generating links. Run `python seed.py` to add
   delegates and update `invites.csv`.
7. Run `python -m uvicorn app:app --host 127.0.0.1 --port 8000` for local
   development, or double-click `run.bat` on Windows to start the app and
   configured named tunnel. The pages are `/` (portal), `/badge?t=<token>`
   (delegate pass), and `/scan` (staff desk).

Staff routes fail closed unless Cloudflare Access is configured. The app
validates each `Cf-Access-Jwt-Assertion` signature, issuer, audience, and
expiration against Cloudflare's published signing keys; the staff key remains
an additional check for staff API operations. The scanner asks volunteers for
that key and keeps it in the browser session only. Rotate it if exposed.

## Public access and pass rotation

Do not expose the app through a tunnel until its stable hostname is protected
by the Cloudflare Access application and volunteer Allow policy above. Keep the
staff key and delegate links private. `run.bat` refuses to launch unless the
named tunnel's local configuration file exists, and the app refuses staff-route
requests unless both Access settings are present and the Access JWT validates.

Delegate links remain valid while their records remain in the database. Changing
`CODE_SECRET` invalidates QR codes already downloaded or printed; delegates can
use their existing invite links to generate replacement passes. Back up the
database and keep `CODE_SECRET` stable during the event.

### Adding delegates without replacing existing invitations

Add rows to `delegates.csv` and run `python seed.py` again. Existing database
records keep their current invite tokens, and existing rows in `invites.csv`
keep their token and link unchanged. The seeder appends invitations only for
delegates that do not already have an invite export row; it does not regenerate
previously issued tokens. It also accepts the current roster headers
`Full Name,Email Address`. If an existing CSV invite token does not match the
database, seeding stops rather than silently changing that invitation.

Treat both CSV files as private attendee data; `invites.csv` contains bearer
tokens that grant access to delegate passes.

Offline scans are queued in the browser and reconciled with the server on sync.
The device prevents repeat admissions already recorded in its local roster or
queue, but separate devices operating offline cannot see one another's scans.
The offline roster and queue are stored in that browser's local storage. Avoid
shared devices and use **Clear Local Data** after syncing at the end of the
event.
