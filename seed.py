import csv
import os
import secrets
import tempfile
from urllib.parse import urlsplit

from app import BASE_DIR, db


BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
CSV_FILE = BASE_DIR / "delegates.csv"
INVITES_FILE = BASE_DIR / "invites.csv"

HEADER_ALIASES = {
    "name": {"name", "full name"},
    "email": {"email", "email address"},
}


def read_delegates():
    if not CSV_FILE.is_file():
        raise SystemExit(f"Error: {CSV_FILE.name} not found.")

    with CSV_FILE.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        columns = {
            field.strip().casefold(): field
            for field in (reader.fieldnames or [])
            if field and field.strip()
        }
        fieldnames = {}
        for canonical, aliases in HEADER_ALIASES.items():
            matches = [columns[alias] for alias in aliases if alias in columns]
            if len(matches) != 1:
                raise SystemExit(
                    "Error: delegates.csv must have one name column "
                    "('name' or 'Full Name') and one email column "
                    "('email' or 'Email Address')."
                )
            fieldnames[canonical] = matches[0]

        delegates = []
        seen_emails = set()
        for line_number, row in enumerate(reader, start=2):
            name = (row.get(fieldnames["name"]) or "").strip()
            email = (row.get(fieldnames["email"]) or "").strip().lower()
            if not name or len(name) > 200:
                raise SystemExit(f"Error: invalid name on delegates.csv line {line_number}.")
            local_part, separator, domain = email.partition("@")
            if (
                len(email) > 320
                or not separator
                or not local_part
                or not domain
                or "@" in domain
                or any(character.isspace() for character in email)
            ):
                raise SystemExit(f"Error: invalid email on delegates.csv line {line_number}.")
            if email in seen_emails:
                raise SystemExit(
                    f"Error: duplicate email on delegates.csv line {line_number}."
                )
            seen_emails.add(email)
            delegates.append({"name": name, "email": email})
        return delegates


def read_existing_invites():
    if not INVITES_FILE.is_file():
        return []

    with INVITES_FILE.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        expected = {"name", "email", "token", "link"}
        if not reader.fieldnames or not expected.issubset(reader.fieldnames):
            raise SystemExit("Error: invites.csv must have name,email,token,link columns.")
        rows = []
        seen_emails = set()
        for line_number, row in enumerate(reader, start=2):
            email = (row.get("email") or "").strip().lower()
            token = (row.get("token") or "").strip()
            if not email or not token or not (row.get("link") or "").strip():
                raise SystemExit(f"Error: incomplete existing invite on invites.csv line {line_number}.")
            if email in seen_emails:
                raise SystemExit(f"Error: duplicate email on invites.csv line {line_number}.")
            seen_emails.add(email)
            rows.append(
                {
                    "name": row["name"],
                    "email": row["email"],
                    "token": row["token"],
                    "link": row["link"],
                }
            )
        return rows


def main():
    parsed_url = urlsplit(BASE_URL)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.netloc
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise SystemExit("Error: BASE_URL must be an http:// or https:// URL without a query or fragment.")

    delegates = read_delegates()
    invite_rows = read_existing_invites()
    invited_emails = {row["email"].strip().lower() for row in invite_rows}
    count_new = 0
    count_existing = 0
    count_invites_added = 0

    with db() as con:
        for invite in invite_rows:
            existing = con.execute(
                "SELECT token FROM delegates WHERE email=?",
                (invite["email"].strip().lower(),),
            ).fetchone()
            if not existing or existing["token"] != invite["token"]:
                raise SystemExit(
                    "Error: an existing invite does not match its database record. "
                    "Reconcile invites.csv before seeding; existing invite tokens were not changed."
                )

        for delegate in delegates:
            existing = con.execute(
                "SELECT name, email, token FROM delegates WHERE email=?",
                (delegate["email"],),
            ).fetchone()
            if existing:
                name = existing["name"]
                email = existing["email"]
                token = existing["token"]
                count_existing += 1
            else:
                name = delegate["name"]
                email = delegate["email"]
                token = secrets.token_urlsafe(32)
                con.execute(
                    "INSERT INTO delegates(name, email, token) VALUES(?,?,?)",
                    (name, email, token),
                )
                count_new += 1
            if email not in invited_emails:
                invite_rows.append(
                    {
                        "name": name,
                        "email": email,
                        "token": token,
                        "link": f"{BASE_URL}/badge?t={token}",
                    }
                )
                invited_emails.add(email)
                count_invites_added += 1

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=BASE_DIR,
            prefix="invites-",
            suffix=".tmp",
            delete=False,
        ) as output:
            temp_path = output.name
            writer = csv.DictWriter(output, fieldnames=["name", "email", "token", "link"])
            writer.writeheader()
            writer.writerows(invite_rows)
        os.replace(temp_path, INVITES_FILE)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)

    print(f"Seeding complete! Added {count_new} new delegates, retained {count_existing} existing.")
    print(f"Added {count_invites_added} new invite(s); existing invite tokens were retained.")
    print(f"Invite export updated at '{INVITES_FILE.name}'.")


if __name__ == "__main__":
    main()
