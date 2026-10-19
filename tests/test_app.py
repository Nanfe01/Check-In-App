import asyncio
import csv
import os
import secrets
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa

os.environ["CODE_SECRET"] = secrets.token_urlsafe(32)
os.environ["STAFF_KEY"] = secrets.token_urlsafe(32)
os.environ["CF_ACCESS_TEAM_DOMAIN"] = "test-team.cloudflareaccess.com"
os.environ["CF_ACCESS_AUD"] = "test-audience"
_BOOTSTRAP_DIR = tempfile.TemporaryDirectory()
os.environ["DB_PATH"] = os.path.join(_BOOTSTRAP_DIR.name, "bootstrap.db")

import app
import seed
import jwt


class CheckinTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        app.DB = os.path.join(self.temp_dir.name, "delegates.db")
        app.init_db()
        with app.db() as con:
            con.execute(
                "INSERT INTO delegates(name, email, token) VALUES(?,?,?)",
                ("Test Delegate", "test@example.com", "test-token"),
            )
            self.delegate_id = con.execute(
                "SELECT id FROM delegates WHERE email=?",
                ("test@example.com",),
            ).fetchone()["id"]
        self.code = app.make_code(self.delegate_id)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_code_parser_rejects_malformed_and_non_ascii_codes(self):
        self.assertEqual(app.parse_code(self.code.lower()), self.delegate_id)
        self.assertIsNone(app.parse_code("SUM-"))
        self.assertIsNone(app.parse_code("SUM０００１-AAAAAAAAAA"))
        self.assertIsNone(app.parse_code("SUM0001-AAAAAAAAAAA"))

    def test_checkin_is_idempotent_and_concurrency_safe(self):
        def admit():
            return app.checkin(app.CheckinBody(code=self.code), app.STAFF_KEY)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: admit(), range(2)))

        self.assertCountEqual([result["status"] for result in results], ["ok", "already"])
        already = next(result for result in results if result["status"] == "already")
        self.assertIsNotNone(already["at"])

    def test_sync_rejects_naive_timestamps_without_checking_in(self):
        result = app.sync_checkins(
            app.SyncBody(checkins=[{"code": self.code, "at": "2026-10-17T09:00:00"}]),
            app.STAFF_KEY,
        )
        self.assertEqual(result["synced"][0]["status"], "invalid_timestamp")
        with app.db() as con:
            row = con.execute(
                "SELECT checked_in_at FROM delegates WHERE id=?",
                (self.delegate_id,),
            ).fetchone()
        self.assertIsNone(row["checked_in_at"])

    def test_sync_normalizes_timezone_aware_timestamps(self):
        result = app.sync_checkins(
            app.SyncBody(checkins=[{"code": self.code, "at": "2026-10-17T10:00:00+01:00"}]),
            app.STAFF_KEY,
        )
        self.assertEqual(result["synced"][0]["status"], "ok")
        self.assertEqual(result["synced"][0]["at"], "2026-10-17T09:00:00+00:00")

    def test_sync_rejects_batches_over_limit(self):
        with self.assertRaises(ValueError):
            app.SyncBody(checkins=[{"code": self.code}] * 501)

    def test_staff_routes_require_cloudflare_access_but_delegate_routes_remain_public(self):
        async def call_next(_request):
            return app.Response(
                "reached handler",
                status_code=200,
                headers={"X-Test-Path": _request.url.path},
            )

        for path in ("/scan", "/api/stats"):
            request = SimpleNamespace(url=SimpleNamespace(path=path), headers={})
            response = asyncio.run(app.disable_api_caching(request, call_next))
            self.assertEqual(response.status_code, 401)

        public_request = SimpleNamespace(url=SimpleNamespace(path="/badge"), headers={})
        public_response = asyncio.run(app.disable_api_caching(public_request, call_next))
        self.assertEqual(public_response.status_code, 200)
        self.assertEqual(public_response.headers["Referrer-Policy"], "no-referrer")

        request = SimpleNamespace(
            url=SimpleNamespace(path="/scan"),
            headers={"Cf-Access-Jwt-Assertion": "valid-access-jwt"},
        )
        with patch.object(app, "verify_access_assertion") as verify:
            response = asyncio.run(app.disable_api_caching(request, call_next))
            self.assertEqual(response.status_code, 200)
            verify.assert_called_once_with("valid-access-jwt")

    def test_staff_routes_fail_closed_when_access_is_unconfigured(self):
        async def call_next(_request):
            return app.Response(
                "reached handler",
                status_code=200,
                headers={"X-Test-Path": _request.url.path},
            )

        request = SimpleNamespace(url=SimpleNamespace(path="/scan"), headers={})
        with (
            patch.object(app, "ACCESS_ISSUER", ""),
            patch.object(app, "ACCESS_AUD", ""),
            patch.object(app, "ACCESS_JWKS_CLIENT", None),
        ):
            response = asyncio.run(app.disable_api_caching(request, call_next))
        self.assertEqual(response.status_code, 503)

    def test_invalid_cloudflare_access_jwt_is_rejected(self):
        async def call_next(_request):
            return app.Response(
                "reached handler",
                status_code=200,
                headers={"X-Test-Path": _request.url.path},
            )

        request = SimpleNamespace(
            url=SimpleNamespace(path="/scan"),
            headers={"Cf-Access-Jwt-Assertion": "invalid-access-jwt"},
        )
        with patch.object(
            app,
            "verify_access_assertion",
            side_effect=jwt.InvalidTokenError("invalid"),
        ):
            response = asyncio.run(app.disable_api_caching(request, call_next))
        self.assertEqual(response.status_code, 401)

    def test_cloudflare_access_jwt_checks_signature_issuer_audience_and_expiry(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = {
            "iss": app.ACCESS_ISSUER,
            "aud": app.ACCESS_AUD,
            "exp": int(time.time()) + 60,
        }
        token = jwt.encode(claims, private_key, algorithm="RS256")
        with patch.object(
            app.ACCESS_JWKS_CLIENT,
            "get_signing_key_from_jwt",
            return_value=SimpleNamespace(key=public_key),
        ):
            app.verify_access_assertion(token)

            wrong_audience = jwt.encode(
                {**claims, "aud": "wrong-audience"},
                private_key,
                algorithm="RS256",
            )
            with self.assertRaises(jwt.InvalidAudienceError):
                app.verify_access_assertion(wrong_audience)

            wrong_signature = jwt.encode(claims, other_private_key, algorithm="RS256")
            with self.assertRaises(jwt.InvalidSignatureError):
                app.verify_access_assertion(wrong_signature)

            wrong_issuer = jwt.encode(
                {**claims, "iss": "https://wrong.cloudflareaccess.com"},
                private_key,
                algorithm="RS256",
            )
            with self.assertRaises(jwt.InvalidIssuerError):
                app.verify_access_assertion(wrong_issuer)

            expired = jwt.encode(
                {**claims, "exp": int(time.time()) - 60},
                private_key,
                algorithm="RS256",
            )
            with self.assertRaises(jwt.ExpiredSignatureError):
                app.verify_access_assertion(expired)

    def test_seed_appends_only_new_invites_and_preserves_existing_tokens(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            roster = Path(temp_dir) / "delegates.csv"
            invites = Path(temp_dir) / "invites.csv"
            roster.write_text(
                "name,email\nFirst Delegate,first@example.com\n",
                encoding="utf-8",
            )
            with patch.object(seed, "CSV_FILE", roster), patch.object(seed, "INVITES_FILE", invites):
                seed.main()
                with invites.open(newline="", encoding="utf-8") as source:
                    initial_rows = list(csv.DictReader(source))
                roster.write_text(
                    "name,email\nFirst Delegate,first@example.com\n"
                    "Second Delegate,second@example.com\n",
                    encoding="utf-8",
                )
                seed.main()
                with invites.open(newline="", encoding="utf-8") as source:
                    after_addition = list(csv.DictReader(source))
                seed.main()
                with invites.open(newline="", encoding="utf-8") as source:
                    after_repeat = list(csv.DictReader(source))

            self.assertEqual(len(initial_rows), 1)
            self.assertEqual(len(after_addition), 2)
            self.assertEqual(after_addition[0], initial_rows[0])
            self.assertEqual(after_repeat, after_addition)
            self.assertNotEqual(after_addition[0]["token"], after_addition[1]["token"])
            self.assertTrue(after_addition[1]["link"].endswith(after_addition[1]["token"]))
            with app.db() as con:
                count = con.execute("SELECT COUNT(*) FROM delegates").fetchone()[0]
            self.assertEqual(count, 3)

    def test_seed_accepts_current_full_name_and_email_address_headers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            roster = Path(temp_dir) / "delegates.csv"
            invites = Path(temp_dir) / "invites.csv"
            roster.write_text(
                "Full Name,Email Address\nCurrent Format,current@example.com\n",
                encoding="utf-8",
            )
            with patch.object(seed, "CSV_FILE", roster), patch.object(seed, "INVITES_FILE", invites):
                seed.main()
            with invites.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["email"], "current@example.com")

    def test_seed_rejects_duplicate_emails_without_overwriting_invites(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            roster = Path(temp_dir) / "delegates.csv"
            invites = Path(temp_dir) / "invites.csv"
            roster.write_text(
                "name,email\nDelegate One,duplicate@example.com\n"
                "Delegate Two,DUPLICATE@example.com\n",
                encoding="utf-8",
            )
            invites.write_text("previous invite file", encoding="utf-8")
            with patch.object(seed, "CSV_FILE", roster), patch.object(seed, "INVITES_FILE", invites):
                with self.assertRaises(SystemExit) as raised:
                    seed.main()

            self.assertNotIn("duplicate@example.com", str(raised.exception))
            self.assertEqual(invites.read_text(encoding="utf-8"), "previous invite file")
            with app.db() as con:
                count = con.execute(
                    "SELECT COUNT(*) FROM delegates WHERE email=?",
                    ("duplicate@example.com",),
                ).fetchone()[0]
            self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
