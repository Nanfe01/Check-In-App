# Summit QR check-in

Registrants get a personal link that shows their QR code. Volunteers scan it on their phones to check people in.

Data is stored in Postgres when `DATABASE_URL` is set (use this when hosting), or in a local SQLite file when it isn't (fine for testing on your computer).

## Run it on your computer (testing)
```bash
pip install -r requirements.txt
# Windows PowerShell:  $env:VOLUNTEER_PASSCODE="your-passcode"
export VOLUNTEER_PASSCODE="your-passcode"
export EVENT_NAME="Your Summit Name"       # optional
export EVENT_DETAILS="Date, venue"         # optional
python -m uvicorn app:app --port 8000
```
Open http://localhost:8000/scan. Delete `checkin.db` after testing.

## Host it for free (Neon database + Render web service)
1. **Database:** create a free project at neon.tech. Copy the connection string (starts with `postgresql://`).
2. **Import your registrants into it** from your own computer, using your final public address:
   ```bash
   export DATABASE_URL="postgresql://...your Neon string..."
   python import_registrants.py registrants.xlsx --base-url https://YOUR-APP.onrender.com
   ```
   This writes `registrants_with_links.xlsx` with a `pass_link` column for your mail merge.
3. **Web service:** push this folder to a GitHub repo, then on render.com create a New > Web Service from it.
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT --proxy-headers`
   - Environment variables: `DATABASE_URL`, `VOLUNTEER_PASSCODE`, `EVENT_NAME`, and optionally `EVENT_DETAILS`, `PYTHON_VERSION=3.12.8`.
   - Choose the Free instance type. Your address will be `https://YOUR-APP.onrender.com`; the service name decides it, so create it first if you want the address before step 2.
4. **Keep it awake:** free web services sleep after about 15 minutes idle, and waking takes 30 to 60 seconds. Create a free monitor (e.g. UptimeRobot) that requests `https://YOUR-APP.onrender.com/healthz` every 5 minutes, starting the day before the event. On event day, open `/scan` 10 minutes before doors to wake the database too.

Free-tier limits change, so check the current terms for Neon and Render before the event. Both sites show them on their pricing pages.

## Volunteers on the day
Open `https://YOUR-APP.onrender.com/scan`, enter a name and the passcode, and scan.
- Green: checked in. Amber: already checked in (shows when and by whom). Red: code not on the list.
- Search tab: find someone by name or email, check in or undo, add walk-ins, download the attendance CSV.

## Notes
- Tokens are random (96 bits) and not derived from names or emails, so passes can't be guessed.
- Check-in is atomic: if two volunteers scan the same code together, only one gets green (tested against Postgres with 25 simultaneous scans).
- The QR and scanner libraries are bundled in `static/vendor`, so no CDN is needed at the venue.
- Re-running the import with an updated sheet only adds new people; existing links keep working.
- Do a full rehearsal with real phones before the event.
