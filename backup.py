#!/usr/bin/env python3
"""Yandex Disk backup for Ubuntu, Python 3.9+ and requests.

OAuth is imported silently from `rclone config show yandex`. Refresh is
delegated to rclone with a private temporary config, preserving its own client
credentials. Refreshed tokens are atomically cached with permissions 0600.
No original rclone configuration is modified.
"""
import argparse
import configparser
import contextlib
import datetime as dt
import fcntl
import json
import logging
import math
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time

import requests

API_URL = "https://cloud-api.yandex.net/v1/disk"
DEFAULT_DB = "/mnt/storage/backup-state/manifest.sqlite"
DEFAULT_ROOT = "/mnt/storage/yandex"
LOG = logging.getLogger("yandex-backup")


class Stopped(Exception):
    pass


class BackupError(Exception):
    """Only fixed, non-secret messages may be passed to this exception."""


def check_stop(stop):
    if stop.is_set():
        raise Stopped()


def safe_error(exc):
    # Never stringify arbitrary requests/OSError/subprocess exceptions: they
    # can contain signed URLs, response bodies, config contents or tokens.
    if isinstance(exc, BackupError):
        return str(exc)
    if isinstance(exc, requests.exceptions.Timeout):
        return "network timeout"
    if isinstance(exc, requests.exceptions.RequestException):
        return "network request failed (details suppressed)"
    if isinstance(exc, OSError):
        return "filesystem/process error (errno=%s)" % exc.errno
    if isinstance(exc, sqlite3.Error):
        return "SQLite error (details suppressed)"
    return "operation failed (%s; details suppressed)" % type(exc).__name__


def db_open(path):
    db = sqlite3.connect(str(path), timeout=60)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=60000")
    return db


def init_db(db):
    db.execute("""CREATE TABLE IF NOT EXISTS files (
        path TEXT PRIMARY KEY, size INTEGER NOT NULL, md5 TEXT,
        modified TEXT, status TEXT DEFAULT 'pending', error TEXT)""")
    required = {"path", "size", "md5", "modified", "status", "error"}
    if not required.issubset({r[1] for r in db.execute("PRAGMA table_info(files)")}):
        raise BackupError("manifest schema is incompatible")
    db.commit()


@contextlib.contextmanager
def exclusive_lock(path):
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError("another backup process holds the lock") from None
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def signal_stop(stop):
    previous = {}
    def handler(signum, frame):
        # No logging/SQLite/locks in a signal handler.
        stop.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, handler)
    try:
        yield
    finally:
        for sig, old in previous.items():
            signal.signal(sig, old)


def private_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".token-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        fd_dir = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd_dir)
        finally:
            os.close(fd_dir)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class Auth:
    def __init__(self, token_path, remote, stop, timeout):
        self.path = Path(token_path).expanduser()
        self.remote = remote
        self.stop = stop
        self.timeout = timeout
        self.lock = threading.Lock()
        self.token = None
        if self.path.exists():
            fd = os.open(str(self.path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                data = json.load(stream)
            if data.get("_remote", remote) != remote:
                raise BackupError("token cache belongs to a different rclone remote")
            self.token = data
        else:
            cfg = self._config()
            self.token = json.loads(cfg[self.remote]["token"])
            self._save()
        if not self.token.get("access_token"):
            raise BackupError("access token is missing; configure rclone remote first")

    def _command(self, args, timeout):
        check_stop(self.stop)
        # Capture both streams; never inherit rclone output containing secrets.
        with subprocess.Popen(["rclone"] + args, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            deadline = time.monotonic() + timeout
            try:
                while True:
                    check_stop(self.stop)
                    if time.monotonic() >= deadline:
                        raise BackupError("rclone command timed out")
                    try:
                        out, _ = proc.communicate(timeout=0.2)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                if proc.returncode:
                    raise BackupError("rclone command failed; check remote configuration locally")
                return out.decode("utf-8")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()

    def _config(self):
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(self._command(["config", "show", self.remote], 30))
        if self.remote not in cfg or cfg[self.remote].get("type") != "yandex":
            raise BackupError("rclone remote is missing or is not type yandex")
        if not cfg[self.remote].get("token"):
            raise BackupError("rclone remote has no OAuth token")
        return cfg

    def _save(self):
        private_json(self.path, dict(self.token, _remote=self.remote))

    def _expired(self):
        expiry = self.token.get("expiry")
        if not expiry or expiry.startswith("0001-"):
            return False
        try:
            end = dt.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if end.tzinfo is None:
                end = end.replace(tzinfo=dt.timezone.utc)
            return end.timestamp() <= time.time() + 60
        except (ValueError, TypeError):
            raise BackupError("invalid token expiry in cache") from None

    def access(self, rejected=None):
        with self.lock:
            check_stop(self.stop)
            # Several workers may receive 401 for the same old token.
            force = rejected is not None and rejected == self.token["access_token"]
            if force or self._expired():
                if not self.token.get("refresh_token"):
                    raise BackupError("refresh token is missing; reconnect rclone remote locally")
                cfg = self._config()
                old = dict(self.token)
                old.pop("_remote", None)
                old["expiry"] = "2000-01-01T00:00:00Z"
                cfg[self.remote]["token"] = json.dumps(old)
                # rclone uses its built-in OAuth client or the custom client
                # from the remote. The temp config also receives token rotation.
                with tempfile.TemporaryDirectory(prefix="yandex-backup-oauth-") as directory:
                    filename = Path(directory) / "rclone.conf"
                    fd = os.open(str(filename), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as stream:
                        cfg.write(stream)
                    self._command(["about", self.remote + ":", "--json", "--config",
                                   str(filename), "--retries", "1", "--low-level-retries", "1",
                                   "--contimeout", str(self.timeout[0]) + "s",
                                   "--timeout", str(self.timeout[1]) + "s"],
                                  sum(self.timeout) + 30)
                    fresh = configparser.ConfigParser(interpolation=None)
                    fresh.read(filename, encoding="utf-8")
                    token = json.loads(fresh[self.remote]["token"])
                if not token.get("access_token") or token.get("expiry") == old["expiry"]:
                    raise BackupError("rclone did not refresh the OAuth token")
                self.token = token
                self._save()
                LOG.info("OAuth token refreshed and saved privately")
            return self.token["access_token"]


class YandexAPI:
    def __init__(self, auth, stop, timeout):
        self.auth, self.stop, self.timeout = auth, stop, timeout
        self.session = requests.Session()

    def close(self):
        self.session.close()

    def get(self, endpoint, **params):
        token = self.auth.access()
        for attempt in range(2):
            check_stop(self.stop)
            with self.session.get(API_URL + endpoint, params=params,
                                  headers={"Authorization": "OAuth " + token},
                                  timeout=self.timeout, allow_redirects=False) as response:
                if response.status_code == 401 and attempt == 0:
                    token = self.auth.access(rejected=token)
                    continue
                if response.status_code != 200:
                    raise BackupError("Disk API HTTP %d" % response.status_code)
                try:
                    return response.json()
                except ValueError:
                    raise BackupError("invalid JSON from Disk API") from None
        raise BackupError("Disk API authentication failed")

    def download_url(self, path):
        value = self.get("/resources/download", path=path)
        from urllib.parse import urlsplit
        href = value.get("href", "")
        parsed = urlsplit(href)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise BackupError("invalid HTTPS download link from Disk API")
        return href


def scan(db, api, stop, attempts, page_size):
    # Upsert, never delete absent rows: an interrupted scan must not erase the
    # manifest. Metadata changes invalidate verified; identical rows preserve it.
    folders, visited, count = ["disk:/"], set(), 0
    while folders:
        check_stop(stop)
        folder = folders.pop()
        if folder in visited:
            continue
        visited.add(folder)
        offset = 0
        while True:
            for attempt in range(attempts):
                try:
                    data = api.get("/resources", path=folder, limit=page_size,
                                   offset=offset, sort="name")
                    break
                except Stopped:
                    raise
                except Exception as exc:
                    if attempt + 1 == attempts:
                        raise
                    LOG.warning("SCAN retry %r: %s", folder, safe_error(exc))
                    if stop.wait(min(2 ** (attempt + 1), 30)):
                        raise Stopped()
            if data.get("type") != "dir" or "_embedded" not in data:
                raise BackupError("unexpected directory metadata")
            items = data["_embedded"].get("items")
            if not isinstance(items, list):
                raise BackupError("invalid directory listing")
            with db:
                for item in items:
                    check_stop(stop)
                    path = item.get("path", "")
                    # Validate containment before trusting a returned API path.
                    if not path.startswith(folder.rstrip("/") + "/"):
                        raise BackupError("API returned a path outside scanned directory")
                    if item.get("type") == "dir":
                        folders.append(path)
                    elif item.get("type") == "file":
                        size = item.get("size")
                        if not isinstance(size, int) or size < 0:
                            raise BackupError("API returned invalid file size")
                        db.execute("""INSERT INTO files(path,size,md5,modified,status,error)
                            VALUES(?,?,?,?, 'pending',NULL)
                            ON CONFLICT(path) DO UPDATE SET
                            status=CASE WHEN files.size=excluded.size
                              AND files.md5 IS excluded.md5 AND files.modified IS excluded.modified
                              THEN files.status ELSE 'pending' END,
                            error=CASE WHEN files.size=excluded.size
                              AND files.md5 IS excluded.md5 AND files.modified IS excluded.modified
                              THEN files.error ELSE NULL END,
                            size=excluded.size, md5=excluded.md5, modified=excluded.modified""",
                                   (path, size, item.get("md5"), item.get("modified")))
                        count += 1
                    else:
                        raise BackupError("API returned unknown resource type")
            offset += len(items)
            LOG.info("SCAN %r: %d entries; files seen: %d", folder, offset, count)
            total = data["_embedded"].get("total")
            if not items or (isinstance(total, int) and offset >= total):
                break
    LOG.info("Scan complete: %d files seen; absent old rows retained", count)


def status(db):
    count, size = db.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM files").fetchone()
    print("Manifest: {:,} files, {:.3f} TB (decimal)".format(count, size / 1e12))
    for row in db.execute("SELECT status,COUNT(*),COALESCE(SUM(size),0) FROM files GROUP BY status"):
        print("{}: {:,} files, {:.3f} GB".format(row[0], row[1], row[2] / 1e9))


def positive(value):
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return value


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("must be between %d and %d" % (low, high))
        return number
    return parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("scan", "status", "download"))
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--dest", default=DEFAULT_ROOT)
    parser.add_argument("--remote", default="yandex")
    parser.add_argument("--token-file", default="~/.config/yandex-backup/token.json")
    parser.add_argument("--workers", type=bounded_int(1, 32), default=4)
    parser.add_argument("--order", choices=("asc", "desc"), default="asc",
                        help="order by size, then path")
    parser.add_argument("--skip-failed", action="store_true",
                        help="skip failed manifest rows for this run; leave their status unchanged")
    parser.add_argument("--read-timeout", type=positive, default=30)
    parser.add_argument("--connect-timeout", type=positive, default=15)
    parser.add_argument("--max-attempts", type=bounded_int(1, 100), default=3)
    parser.add_argument("--page-size", type=bounded_int(1, 1000), default=1000)
    parser.add_argument("--progress-interval", type=positive, default=30)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()
    db_path = Path(args.db).expanduser().resolve()
    try:
        if args.command != "scan" and not db_path.is_file():
            raise BackupError("manifest is missing; run scan first or check --db")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with signal_stop(stop), contextlib.ExitStack() as stack:
            # status is read-only and can run during downloads.
            if args.command != "status":
                stack.enter_context(exclusive_lock(str(db_path) + ".lock"))
            db = stack.enter_context(contextlib.closing(db_open(db_path)))
            if args.command == "status":
                status(db)
                return 0
            init_db(db)
            token_path = Path(args.token_file).expanduser()
            token_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stack.enter_context(exclusive_lock(str(token_path) + ".lock"))
            timeout = (args.connect_timeout, args.read_timeout)
            auth = Auth(token_path, args.remote, stop, timeout)
            if args.command == "scan":
                api = YandexAPI(auth, stop, timeout)
                stack.callback(api.close)
                scan(db, api, stop, args.max_attempts, args.page_size)
            else:
                import downloader
                root = Path(args.dest).expanduser().resolve()
                root.mkdir(parents=True, exist_ok=True)
                # Root inode lock: no reserved lock filename inside the backup.
                root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
                stack.callback(os.close, root_fd)
                try:
                    fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise BackupError("another downloader is using this destination") from None
                failures = downloader.run(db, root, auth, stop, timeout,
                                          args.workers, args.order, args.max_attempts,
                                          args.progress_interval, skip_failed=args.skip_failed)
                if stop.is_set():
                    LOG.info("Stopped; partial files retained, unfinished rows remain retryable")
                    return 130
                return 1 if failures else 0
        return 0
    except (Stopped, KeyboardInterrupt):
        LOG.info("Stopped; committed manifest and partial files retained")
        return 130
    except Exception as exc:
        LOG.error("%s", safe_error(exc))
        return 1


if __name__ == "__main__":
    # downloader imports these shared types; keep one module instance when
    # backup.py was invoked as a script rather than imported as a library.
    import sys
    sys.modules.setdefault("backup", sys.modules[__name__])
    raise SystemExit(main())

