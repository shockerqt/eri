#!/usr/bin/env python3
"""Synthetic, isolated PostgreSQL 17 fixtures for provider-logout-proof.sql."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid


PROOF_SQL = Path(__file__).with_name("provider-logout-proof.sql").read_text()
OPERATION_ID = "d" * 32
CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")


def run(argv, input_text=None):
    return subprocess.run(
        [str(arg) for arg in argv], input=input_text, text=True,
        capture_output=True, check=True,
    ).stdout.strip()


class Database:
    def __init__(self, container, postgres_bin):
        self.container = container
        self.postgres_bin = Path(postgres_bin)
        self.directory = None
        self.started = False

    def __enter__(self):
        if self.container:
            return self
        self.directory = Path(tempfile.mkdtemp(prefix="eri-provider-proof-pg-"))
        data = self.directory / "data"
        socket = self.directory / "socket"
        socket.mkdir()
        try:
            run([self.postgres_bin / "initdb", "-D", data, "-A", "trust", "-U", "postgres", "--no-locale"])
            run([self.postgres_bin / "pg_ctl", "-D", data, "-l", self.directory / "postgres.log",
                 "-o", f"-k {socket} -h '' -p 5432", "-w", "start"])
            self.started = True
        except Exception:
            shutil.rmtree(self.directory)
            raise
        return self

    def __exit__(self, *_):
        if self.directory:
            try:
                if self.started:
                    run([self.postgres_bin / "pg_ctl", "-D", self.directory / "data",
                         "-m", "immediate", "-w", "stop"])
            finally:
                shutil.rmtree(self.directory)

    def query(self, sql, operation_id=OPERATION_ID):
        if self.container:
            argv = ["docker", "exec", "--user", "postgres", "-i", self.container,
                    "psql", "-X", "-qAt", "--set", "ON_ERROR_STOP=1",
                    "--set", "operation_id=" + operation_id,
                    "-U", "postgres", "-d", "eri_inf008_test"]
        else:
            argv = [self.postgres_bin / "psql", "-X", "-qAt", "--set", "ON_ERROR_STOP=1",
                    "--set", "operation_id=" + operation_id,
                    "-h", self.directory / "socket", "-U", "postgres", "-d", "postgres"]
        return run(argv, sql)


def quote(value):
    return "'" + value.replace("'", "''") + "'"


def fixtures():
    keys = ["sa", "sb", "ca", "cb", "fa", "fb", "ma", "na", "mb", "nb", "logout", "extra"]
    ids = {key: str(uuid.UUID(int=index + 1)) for index, key in enumerate(keys)}
    uid = lambda key: quote(ids[key])
    now = datetime.now(timezone.utc)
    instant = lambda seconds: quote((now + timedelta(seconds=seconds)).isoformat()) + "::timestamptz"
    t0, t1, t2, t3, t4, tlate = (instant(s) for s in (-240, -180, -120, -60, 86400, -30))
    client = quote("balance-mobile-staging")
    resource = quote("https://balance-staging.shocker.cl/api")
    schema = """
SET search_path=pg_temp;
CREATE TEMP TABLE provider_sessions(id uuid PRIMARY KEY,expires_at timestamptz,revoked_at timestamptz);
CREATE TEMP TABLE authorization_codes(id uuid PRIMARY KEY,oidc_nonce text,session_id uuid,client_id text,resource text,consumed_at timestamptz);
CREATE TEMP TABLE refresh_families(id uuid PRIMARY KEY,source_code_id uuid,session_id uuid,client_id text,resource text,expires_at timestamptz,revoked_at timestamptz);
CREATE TEMP TABLE refresh_token_members(id uuid PRIMARY KEY,family_id uuid,consumed_at timestamptz,successor_id uuid,issued_at timestamptz);
CREATE TEMP TABLE logout_challenges(id uuid PRIMARY KEY,session_id uuid,client_id text,post_logout_redirect_uri text,downstream_state text,consumed_at timestamptz);
"""
    base = f"""
INSERT INTO provider_sessions VALUES({uid('sa')},{t4},{t3}),({uid('sb')},{t4},{t3});
INSERT INTO authorization_codes VALUES
({uid('ca')},'bal033v1.{OPERATION_ID}.A.{'e'*32}',{uid('sa')},{client},{resource},{t0}),
({uid('cb')},'bal033v1.{OPERATION_ID}.B.{'f'*32}',{uid('sa')},{client},{resource},{t0});
INSERT INTO refresh_families VALUES
({uid('fa')},{uid('ca')},{uid('sa')},{client},{resource},{t4},{t2}),
({uid('fb')},{uid('cb')},{uid('sa')},{client},{resource},{t4},{t3});
INSERT INTO refresh_token_members VALUES
({uid('ma')},{uid('fa')},{t1},{uid('na')},{t0}),({uid('na')},{uid('fa')},NULL,NULL,{t1}),
({uid('mb')},{uid('fb')},{t1},{uid('nb')},{t0}),({uid('nb')},{uid('fb')},NULL,NULL,{t1});
INSERT INTO logout_challenges VALUES
({uid('logout')},{uid('sa')},{client},'balance-dev://logout-callback','{OPERATION_ID}{'a'*32}',{t3});
"""
    cases = [
        ("complete", "", True),
        ("missing_b", f"DELETE FROM refresh_families WHERE id={uid('fb')}", False),
        ("different_provider", f"UPDATE refresh_families SET session_id={uid('sb')} WHERE id={uid('fb')}; UPDATE authorization_codes SET session_id={uid('sb')} WHERE id={uid('cb')}", False),
        ("duplicate_authorization", f"INSERT INTO authorization_codes SELECT {uid('extra')},oidc_nonce,session_id,client_id,resource,consumed_at FROM authorization_codes WHERE id={uid('ca')}", False),
        ("missing_rotation", f"DELETE FROM refresh_token_members WHERE family_id={uid('fb')}", False),
        ("unconsumed_logout", "UPDATE logout_challenges SET consumed_at=NULL", False),
        ("b_revoked_before_browser", f"UPDATE refresh_families SET revoked_at={t2} WHERE id={uid('fb')}", False),
        ("session_not_revoked", "UPDATE provider_sessions SET revoked_at=NULL", False),
        ("wrong_resource", f"UPDATE authorization_codes SET resource='https://wrong.example/api' WHERE id={uid('cb')}", False),
        ("a_not_explicitly_revoked", f"UPDATE refresh_families SET revoked_at={t3} WHERE id={uid('fa')}", False),
        ("expired_b", f"UPDATE refresh_families SET expires_at={t2} WHERE id={uid('fb')}", False),
        ("expired_after_logout", f"UPDATE refresh_families SET expires_at={tlate} WHERE id={uid('fb')}", False),
        ("session_expired_after_logout", f"UPDATE provider_sessions SET expires_at={tlate}", False),
        ("malformed_nonce", f"UPDATE authorization_codes SET oidc_nonce='bal033v1.{OPERATION_ID}.B.invalid' WHERE id={uid('cb')}", False),
    ]
    return schema, base, cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-container", default=os.environ.get("ERI_PROVIDER_PROOF_CONTAINER"))
    parser.add_argument("--postgres-bin", default="/usr/lib/postgresql/17/bin")
    args = parser.parse_args()
    if args.postgres_container and not CONTAINER_ID.fullmatch(args.postgres_container):
        parser.error("PostgreSQL container ID must be 12–64 lowercase hexadecimal characters")

    schema, base, cases = fixtures()
    invalid_references = ["%", "' OR true --", "A" * 32, "d" * 31]
    with Database(args.postgres_container, args.postgres_bin) as db:
        version = int(db.query("SHOW server_version_num;"))
        if version < 170000 or version >= 180000:
            raise RuntimeError("fixtures require PostgreSQL 17")
        for name, mutation, expected in cases:
            result = json.loads(db.query(schema + base + mutation + ";\n" + PROOF_SQL))
            assert result["provider_evidence_complete"] is expected, name
            assert all(isinstance(value, (bool, int)) for value in result.values()), name
        for reference in invalid_references:
            result = json.loads(db.query(schema + base + PROOF_SQL, reference))
            assert result["provider_evidence_complete"] is False, "invalid reference"
            assert result["valid_reference"] is False, "invalid reference"
            assert all(value == 0 for key, value in result.items() if key.endswith("_count")), "invalid reference"
    print(json.dumps({"postgres": "17", "fixture_cases": len(cases) + len(invalid_references),
                      "passed": True, "live_database_read": False,
                      "temporary_tables_only": True}))


if __name__ == "__main__":
    main()
