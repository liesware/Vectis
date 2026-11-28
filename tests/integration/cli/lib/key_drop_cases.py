import errno
import csv
import fcntl
import io
import json
import os
import pty
import resource
import select
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from .cli_support import ROOT, empty_config, require, run_cli, run_cli_json, write_config
from support.vectis import vectis_command


def prepare_key_drop_cases(env):
    kids = {}
    for state in ("active", "disabled", "retired", "compromised", "destroyed"):
        kid = run_cli_json(["keys", "create", "--tag", f"cli-drop-{state}",
                            "--profile", "hybrid-performance-v1"], env)["kid"]
        require(len(kid) == 64 and all(char in "0123456789abcdef" for char in kid), "fixture KID must be hexadecimal")
        if state != "active":
            run_cli(["lifecycle", kid, "--status", state, "--reason", "offline purge test"], env)
        kids[state] = kid
    return kids


class TerminalDrop:
    def __init__(self, env, kid, *, prompt=True, options=(), stdout=subprocess.PIPE, preexec_fn=None, output_format="json"):
        self.master, slave = pty.openpty()
        self.slave = slave
        try:
            self.process = subprocess.Popen(
                vectis_command(["keys", "drop", kid, *options, "--output", output_format], env=env, quiet=True),
                cwd=ROOT, env=env, stdin=slave, stderr=slave, stdout=stdout,
                start_new_session=True, preexec_fn=preexec_fn,
            )
        except BaseException:
            os.close(slave)
            os.close(self.master)
            raise
        self.stderr = bytearray()
        if prompt:
            try:
                deadline = time.monotonic() + 20
                while b"Type 'delete' to confirm:" not in self.stderr:
                    require(time.monotonic() < deadline, "drop prompt timed out")
                    require(self._read(1), "drop exited before confirmation: " + self.stderr.decode(errors="replace"))
            except BaseException:
                self.close()
                raise

    def _read(self, timeout):
        ready, _, _ = select.select([self.master], [], [], timeout)
        if ready:
            try:
                chunk = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                return False
            if not chunk:
                return False
            self.stderr.extend(chunk)
        return True

    def finish(self, response=b"delete\n", interrupt=False):
        if interrupt:
            os.kill(self.process.pid, signal.SIGINT)
        elif response is not None:
            os.write(self.master, response)
        try:
            output, _ = self.process.communicate(timeout=20)
            while self._read(0):
                if not select.select([self.master], [], [], 0)[0]:
                    break
            return self.process.returncode, (output or b"").decode(), self.stderr.decode(errors="replace")
        finally:
            self.close()

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
        if self.master is not None:
            os.close(self.master)
            os.close(self.slave)
            self.master = None


def _audit_records(child):
    audit = Path(child["VECTIS_LOG_DIR"]) / "audit.log"
    return audit, [json.loads(line) for line in audit.read_text().splitlines()]


def _drop_events(records, kid):
    return [r["event"] for r in records if r.get("event", "").startswith("key.drop.") and r.get("kid") == kid]


def _snapshot(database):
    with sqlite3.connect(database) as db:
        return {table: db.execute(f"SELECT * FROM {table} ORDER BY 1, 2").fetchall()
                for table in ("opskeys", "tokens", "subjects", "indexes")}


def key_drop_offline_cases(env, kids, directory):
    target = kids["destroyed"]
    config_paths = [Path(env[name]) for name in ("VECTIS_CONFIG_PATH", "VECTIS_CONFIG_SIGN_PATH")]
    config_before = [path.read_bytes() for path in config_paths]
    with tempfile.TemporaryDirectory(prefix="drop-", dir=directory) as root:
        root = Path(root)
        sequence = 0

        def fixture():
            nonlocal sequence
            sequence += 1
            case = root / str(sequence)
            case.mkdir()
            database = case / "data.db"
            with sqlite3.connect(env["VECTIS_SQLITE_PATH"]) as source, sqlite3.connect(database) as db:
                source.backup(db)
                db.executemany("INSERT INTO tokens VALUES (?, ?, ?, NULL)", [(target, str(i), "synthetic") for i in range(2)])
                db.executemany("INSERT INTO subjects VALUES (?, ?, ?)", [(target, str(i), "synthetic") for i in range(2)])
                db.executemany("INSERT INTO indexes VALUES (?, ?)", [(target, str(i)) for i in range(3)])
            child = dict(env, VECTIS_SQLITE_PATH=str(database), VECTIS_LOG_DIR=str(case / "logs"),
                         VECTIS_API_URL="not-a-url", VECTIS_APIKEY="UNUSED_CANARY",
                         VECTIS_CONFIG_PATH=str(case / "missing-config.json"),
                         VECTIS_CONFIG_SIGN_PATH=str(case / "missing-signature.json"), VECTIS_MODE="prod")
            return child, database

        for response, interrupt in [(b"\n", False), (b"DELETE\n", False), (b"delete \n", False),
                                    (b"x" * 128 + b"\n", False), (b"\x04", False), (None, True)]:
            child, database = fixture()
            before = _snapshot(database)
            code, output, errors = TerminalDrop(child, target).finish(response, interrupt)
            require(code != 0 and output == "" and "cancelled" in errors,
                    f"confirmation must explicitly cancel (response={response!r}, interrupt={interrupt}, exit={code}, stdout={output!r}, stderr={errors!r})")
            require(_snapshot(database) == before, "cancelled purge changed records")

        for kid in ["not-a-kid", "0" * 64, *(kids[state] for state in ("active", "disabled", "retired", "compromised"))]:
            child, database = fixture()
            before = _snapshot(database)
            code, output, _ = TerminalDrop(child, kid, prompt=False).finish(None)
            require(code != 0 and output == "" and _snapshot(database) == before, "invalid or non-destroyed key must not be purged")
        for option in ("--yes", "--force", "--confirm", "extra", "help"):
            child, database = fixture()
            before = _snapshot(database)
            code, _, _ = TerminalDrop(child, target, prompt=False, options=[option]).finish(None)
            require(code != 0 and _snapshot(database) == before, "automatic confirmation and extra arguments must fail")

        child, database = fixture()
        missing = database.parent / "missing.db"
        child["VECTIS_SQLITE_PATH"] = str(missing)
        code, _, _ = TerminalDrop(child, target, prompt=False).finish(None)
        require(code != 0 and not missing.exists(), "missing database must not be created")
        missing.touch()
        code, _, _ = TerminalDrop(child, target, prompt=False).finish(None)
        with sqlite3.connect(missing) as db:
            require(code != 0 and not db.execute("SELECT name FROM sqlite_master").fetchall(),
                    "incompatible schema must fail without initializing tables")

        for mutation in ("properties", "binding", "keys"):
            child, database = fixture()
            with sqlite3.connect(database) as db:
                if mutation == "binding":
                    properties = db.execute("SELECT properties FROM opskeys WHERE kid = ?", (kids["active"],)).fetchone()[0]
                    db.execute("UPDATE opskeys SET properties = ? WHERE kid = ?", (properties, target))
                else:
                    blob = db.execute(f"SELECT {mutation} FROM opskeys WHERE kid = ?", (target,)).fetchone()[0]
                    blob = ("A" if blob[0] != "A" else "B") + blob[1:]
                    db.execute(f"UPDATE opskeys SET {mutation} = ? WHERE kid = ?", (blob, target))
            before = _snapshot(database)
            code, _, _ = TerminalDrop(child, target, prompt=False).finish(None)
            require(code != 0 and _snapshot(database) == before, "unauthenticated material must not be purged")

        for mutation in ("keys", "properties", "missing"):
            child, database = fixture()
            process = TerminalDrop(child, target)
            with sqlite3.connect(database) as db:
                if mutation == "missing":
                    db.execute("DELETE FROM opskeys WHERE kid = ?", (target,))
                else:
                    db.execute(f"UPDATE opskeys SET {mutation} = 'changed' WHERE kid = ?", (target,))
            before = _snapshot(database)
            code, _, errors = process.finish()
            require(code != 0 and _snapshot(database) == before, "stale preflight must not delete dependents")
            audit, records = _audit_records(child)
            require(_drop_events(records, target) == ["key.drop.started", "key.drop.failed"],
                    f"failed purge must audit its start and failure ({mutation}): " + errors)
            run_cli(["audit", "verify", "--file", str(audit)], child)

        child, database = fixture()
        before = _snapshot(database)
        result = run_cli(["keys", "drop", target], child, expect_success=False)
        require("terminal stdin and stderr" in result.stderr and _snapshot(database) == before, "piped confirmation is forbidden")
        master, slave = pty.openpty()
        try:
            result = subprocess.run(vectis_command(["keys", "drop", target], env=child, quiet=True),
                                    cwd=ROOT, env=child, stdin=slave, capture_output=True, timeout=20)
            require(result.returncode != 0 and b"terminal stdin and stderr" in result.stderr,
                    "terminal input alone is insufficient without a visible stderr prompt")
        finally:
            os.close(master)
            os.close(slave)
        child["VECTIS_LOG_TARGET"] = "stdout"
        code, output, _ = TerminalDrop(child, target, prompt=False).finish(None)
        require(code != 0 and output == "" and _snapshot(database) == before, "stdout logging must fail before installation")

        child, database = fixture()
        before = _snapshot(database)
        audit = Path(child["VECTIS_LOG_DIR"]) / "audit.log"
        audit.mkdir(parents=True)
        code, _, _ = TerminalDrop(child, target, prompt=False).finish(None)
        require(code != 0 and _snapshot(database) == before, "unavailable audit must block deletion")

        for kind in ("symlink-inside", "symlink-outside", "symlink-missing", "fifo", "fifo-reader", "socket"):
            child, database = fixture()
            before = _snapshot(database)
            with tempfile.TemporaryDirectory(prefix="va-", dir="/tmp") as audit_directory:
                audit_directory = Path(audit_directory)
                child["VECTIS_LOG_DIR"] = str(audit_directory)
                audit = audit_directory / "audit.log"
                target_path = (audit_directory if kind == "symlink-inside" else database.parent) / "secret-canary-target"
                reader = None
                listener = None
                if kind.startswith("symlink"):
                    if kind != "symlink-missing":
                        target_path.write_bytes(b"secret-canary unchanged")
                    audit.symlink_to(target_path)
                elif kind.startswith("fifo"):
                    os.mkfifo(audit)
                    if kind == "fifo-reader":
                        reader = os.open(audit, os.O_RDONLY | os.O_NONBLOCK)
                else:
                    listener = socket.socket(socket.AF_UNIX)
                    listener.bind(str(audit))
                try:
                    code, output, errors = TerminalDrop(child, target, prompt=False).finish(None)
                    require(code != 0 and output == "" and _snapshot(database) == before,
                            f"unsafe audit destination must block deletion ({kind})")
                    require("VECTIS_AUDIT_LOG_FILE" in errors and "nothing was deleted" in errors,
                            f"unsafe audit failure must identify its pre-delete phase ({kind})")
                    require("secret-canary" not in errors and str(audit) not in errors,
                            "audit errors must not disclose paths or target contents")
                    if kind.startswith("symlink"):
                        if kind == "symlink-missing":
                            require(not target_path.exists(), "dangling audit symlink target was created")
                        else:
                            require(target_path.read_bytes() == b"secret-canary unchanged", "audit symlink target was modified")
                    if reader is not None:
                        require(os.read(reader, 65536) == b"", "non-regular audit received data")
                finally:
                    if reader is not None:
                        os.close(reader)
                    if listener is not None:
                        listener.close()

        child, database = fixture()
        process = TerminalDrop(child, target)
        audit = Path(child["VECTIS_LOG_DIR"]) / "audit.log"
        saved = audit.with_name("saved-audit.log")
        destination_file = database.parent / "secret-canary-destination"
        destination_file.write_bytes(b"unchanged")
        audit.rename(saved)
        audit.symlink_to(destination_file)
        code, _, errors = process.finish()
        require(code == 0, "purge must use its already-open locked audit descriptor: " + errors)
        require(destination_file.read_bytes() == b"unchanged", "purge reopened the replaced audit path")
        require(not any(row[0] == target for row in _snapshot(database)["opskeys"]), "descriptor-preserving purge did not complete")
        records = [json.loads(line) for line in saved.read_text().splitlines()]
        require(_drop_events(records, target) == ["key.drop.started", "key.drop.completed"], "purge audit was not written to the locked file")
        run_cli(["audit", "verify", "--file", str(saved)], child)

        child, database = fixture()
        logs = Path(child["VECTIS_LOG_DIR"])
        real_logs = database.parent / "real-logs"
        real_logs.mkdir()
        logs.symlink_to(real_logs, target_is_directory=True)
        code, _, errors = TerminalDrop(child, target).finish()
        require(code == 0, "trusted symlinked log directory must remain supported: " + errors)
        run_cli(["audit", "verify", "--file", str(real_logs / "audit.log")], child)

        child, database = fixture()
        before = _snapshot(database)
        audit = Path(child["VECTIS_LOG_DIR"]) / "audit.log"
        audit.parent.mkdir(parents=True)
        with audit.open("a") as locked:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, _, errors = TerminalDrop(child, target).finish()
        require(code != 0 and "locked" in errors and _snapshot(database) == before, "audit contention must block deletion")

        child, database = fixture()
        first = TerminalDrop(child, target)
        second = TerminalDrop(child, target)
        os.write(first.master, b"delete\n")
        os.write(second.master, b"delete\n")
        first_result = first.finish(None)
        second_result = second.finish(None)
        require(sum(result[0] == 0 for result in (first_result, second_result)) == 1,
                "duplicate purge must have exactly one success")

        child, database = fixture()
        read_end, broken_stdout = os.pipe()
        os.close(read_end)
        try:
            code, _, errors = TerminalDrop(child, target, stdout=broken_stdout).finish()
        finally:
            os.close(broken_stdout)
        require(code != 0 and "already committed" in errors, "output failure must not claim rollback: " + errors)
        require(not any(row[0] == target for row in _snapshot(database)["opskeys"]), "purge should already be committed")

        child, database = fixture()
        code, output, errors = TerminalDrop(child, target, output_format="yaml").finish()
        require(code == 0 and f"kid: {target}\n" in output and "deleted:\n" in output,
                "YAML purge output failed: " + errors)
        require(all(f"  {table}: {count}\n" in output for table, count in
                    {"opskeys": 1, "tokens": 2, "subjects": 2, "indexes": 3}.items()), "YAML purge counts")

        child, database = fixture()
        child.pop("VECTIS_APIKEY", None)
        child.pop("VECTIS_APIKEY_HASH", None)
        before = _snapshot(database)
        code, output, errors = TerminalDrop(child, target).finish(b"delete\r\n")
        require(code == 0, "offline purge failed: " + errors)
        require(json.loads(output) == {"kid": target, "deleted": {"opskeys": 1, "tokens": 2, "subjects": 2, "indexes": 3}}, "purge counts and JSON output")
        after = _snapshot(database)
        require(all(rows == [row for row in before[table] if row[0] != target] for table, rows in after.items()), "purge must isolate the KID")
        audit, records = _audit_records(child)
        require(_drop_events(records, target) == ["key.drop.started", "key.drop.completed"],
                "purge must audit its start before completion")
        completed = [r for r in records if r.get("event") == "key.drop.completed"]
        require(len(completed) == 1 and completed[0]["actor"] == "offline" and not completed[0]["root"], "honest offline audit attribution")
        require(completed[0]["reason"] == "opskeys=1;tokens=2;subjects=2;indexes=3", "audit deletion counts")
        require("UNUSED_CANARY" not in output + errors + audit.read_text(), "secret canary leaked")
        run_cli(["audit", "verify", "--file", str(audit)], child)
        _restart_after_drop(dict(env, VECTIS_SQLITE_PATH=str(database), VECTIS_LOG_DIR=str(root / "restart-logs")), target)
        if os.environ.get("VECTIS_TEST_POSTGRES_DSN"):
            _postgres_drop_cases(env, kids, root)
        else:
            print("- PostgreSQL CLI purge and post-commit audit failure: SKIPPED (no disposable DSN)", flush=True)
    require([path.read_bytes() for path in config_paths] == config_before, "purge modified signed configuration")
    print("- offline key purge, terminal confirmation, CAS, audit and restart: OK", flush=True)


def _postgres_drop_cases(env, kids, root):
    dsn = os.environ["VECTIS_TEST_POSTGRES_DSN"]
    target = kids["destroyed"]

    def psql(sql):
        result = subprocess.run(["psql", "--no-psqlrc", "--dbname", dsn, "-v", "ON_ERROR_STOP=1", "-At"],
                                input=sql, text=True, capture_output=True, timeout=20)
        require(result.returncode == 0, "disposable PostgreSQL fixture command failed")
        return result.stdout

    def prepare():
        with sqlite3.connect(env["VECTIS_SQLITE_PATH"]) as db:
            row = db.execute("SELECT * FROM opskeys WHERE kid = ?", (target,)).fetchone()
        text = io.StringIO()
        csv.writer(text).writerow(row)
        psql("COPY opskeys FROM STDIN WITH (FORMAT csv);\n" + text.getvalue() + "\\.\n")
        psql(f"INSERT INTO tokens VALUES ('{target}', 'first', 'synthetic', NULL), ('{target}', 'second', 'synthetic', NULL);\n"
             f"INSERT INTO subjects VALUES ('{target}', 'first', 'synthetic'), ('{target}', 'second', 'synthetic');\n"
             f"INSERT INTO indexes VALUES ('{target}', 'first'), ('{target}', 'second'), ('{target}', 'third');\n")

    def absent():
        for table in ("opskeys", "tokens", "subjects", "indexes"):
            require(psql(f"SELECT COUNT(*) FROM {table} WHERE kid = '{target}';\n").strip() == "0",
                    "PostgreSQL purge must remove all dependent rows")

    child = dict(env, VECTIS_STORAGE="postgres", VECTIS_POSTGRES_DSN=dsn,
                 VECTIS_API_URL="invalid-unused", VECTIS_APIKEY="UNUSED_CANARY",
                 VECTIS_CONFIG_PATH=str(root / "missing-config.json"),
                 VECTIS_CONFIG_SIGN_PATH=str(root / "missing-signature.json"),
                 VECTIS_SQLITE_PATH=str(root / "absent-sqlite.db"), VECTIS_MODE="prod",
                 VECTIS_LOG_DIR=str(root / "postgres-success"))
    prepare()
    code, output, errors = TerminalDrop(child, target).finish()
    require(code == 0, "PostgreSQL offline purge failed: " + errors)
    require(json.loads(output)["deleted"] == {"opskeys": 1, "tokens": 2, "subjects": 2, "indexes": 3}, "PostgreSQL purge counts")
    absent()
    audit, records = _audit_records(child)
    require(_drop_events(records, target) == ["key.drop.started", "key.drop.completed"],
            "PostgreSQL purge must audit its start before completion")
    run_cli(["audit", "verify", "--file", str(audit)], child)
    content = audit.read_bytes()
    started = content.index(b'"key.drop.started"')
    audit_bytes_through_started = content.index(b"\n", started) + 1

    prepare()
    child["VECTIS_LOG_DIR"] = str(root / "postgres-audit-failure")

    def limit_audit_size():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (audit_bytes_through_started + 16, audit_bytes_through_started + 16))

    code, output, errors = TerminalDrop(child, target, preexec_fn=limit_audit_size).finish()
    require(code != 0 and output == "" and "already committed" in errors,
            "audit failure after commit must report the confirmed deletion: " + errors)
    absent()
    print("- PostgreSQL CLI purge and post-commit audit failure: OK", flush=True)


def _restart_after_drop(env, kid):
    env = dict(env, VECTIS_CONFIG_PATH=str(Path(env["VECTIS_LOG_DIR"]).parent / "restart-config.json"),
               VECTIS_CONFIG_SIGN_PATH=str(Path(env["VECTIS_LOG_DIR"]).parent / "restart-signature.json"))
    write_config(env, empty_config())
    run_cli(["config", "sign"], env)
    with tempfile.TemporaryFile() as log:
        server = subprocess.Popen(vectis_command(["serve"], env=env, quiet=True), cwd=ROOT, env=env,
                                  stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while True:
                if server.poll() is not None:
                    log.seek(0)
                    raise RuntimeError("purged database server exited: " + log.read().decode(errors="replace")[-2000:])
                ready = subprocess.run(vectis_command(["health", "ready"], env=env, quiet=True), cwd=ROOT, env=env,
                                       capture_output=True, timeout=5)
                if ready.returncode == 0:
                    break
                require(time.monotonic() < deadline, "purged database readiness timed out")
            listed = run_cli_json(["keys", "list"], env)
            require(all(row["kid"] != kid for row in listed["keys"]), "purged KID reappeared after restart")
        finally:
            if server.poll() is None:
                os.killpg(server.pid, signal.SIGINT)
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait()
