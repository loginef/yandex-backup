#!/usr/bin/env python3
"""Streaming downloader; invoked by backup.py, not a separate CLI.

Existing verified rows are trusted and skipped. Other existing final files are
checked but never replaced. Partials resume with HTTP Range when supported;
size and full MD5 are required before publication. Missing manifest MD5 is
fetched from metadata and persisted before scheduling the download.
"""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import logging
import os
from pathlib import Path
import re
import stat
import threading
import time

import requests

from backup import BackupError, Stopped, YandexAPI, check_stop, safe_error

LOG = logging.getLogger("yandex-backup")
CHUNK = 1024 * 1024


def digest_new():
    # MD5 is integrity metadata, not authentication.
    return hashlib.md5(usedforsecurity=False)


def local_path(root, remote):
    if not isinstance(remote, str) or not remote.startswith("disk:/"):
        raise BackupError("unsupported manifest path; expected disk:/")
    parts = remote[6:].split("/")
    if not parts or any(p in ("", ".", "..") or "\x00" in p for p in parts):
        raise BackupError("unsafe manifest path")
    path = root.joinpath(*parts)
    current = root
    for piece in parts:
        current = current / piece
        if current.is_symlink():
            raise BackupError("symlink in destination path; refusing to follow it")
    return path


def open_regular(path, flags):
    fd = os.open(str(path), flags | os.O_NOFOLLOW, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise BackupError("destination or partial is not a regular file")
    return fd


def hash_stream(stream, stop):
    digest, length = digest_new(), 0
    while True:
        check_stop(stop)
        chunk = stream.read(CHUNK)
        if not chunk:
            break
        digest.update(chunk)
        length += len(chunk)
    return length, digest


def verify_file(path, size, md5, stop):
    with os.fdopen(open_regular(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
        if os.fstat(stream.fileno()).st_size != size:
            raise BackupError("existing file size mismatch; original file preserved")
        length, digest = hash_stream(stream, stop)
    if length != size or digest.hexdigest() != md5:
        raise BackupError("existing file MD5 mismatch; original file preserved")


def fsync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(part, final, size, md5, stop):
    check_stop(stop)
    # link() atomically creates the final name, failing if ANY entry exists.
    # Both names are in the same directory/filesystem. Never use replace().
    try:
        os.link(str(part), str(final), follow_symlinks=False)
    except FileExistsError:
        verify_file(final, size, md5, stop)
    fsync_directory(final.parent)
    part.unlink()
    fsync_directory(final.parent)


class Progress:
    def __init__(self):
        self.lock = threading.Lock()
        self.bytes = 0

    def add(self, number):
        with self.lock:
            self.bytes += number

    def read(self):
        with self.lock:
            return self.bytes


def transfer(api, row, root, stop, timeout, progress):
    remote, size, md5 = row["path"], row["size"], row["md5"]
    if not isinstance(size, int) or size < 0:
        raise BackupError("invalid manifest size")
    if not isinstance(md5, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", md5):
        raise BackupError("manifest MD5 is missing or invalid")
    md5 = md5.lower()
    final = local_path(root, remote)
    if os.path.lexists(final):
        verify_file(final, size, md5, stop)
        return "EXISTING"
    final.parent.mkdir(parents=True, exist_ok=True)
    # Recheck after directory creation (reject existing symlink parents).
    local_path(root, remote)
    part = Path(str(final) + ".ydb-part")
    if part.is_symlink():
        raise BackupError("partial path is a symlink")
    fd = open_regular(part, os.O_CREAT | os.O_RDWR | os.O_NONBLOCK)
    with os.fdopen(fd, "r+b") as stream:
        offset, digest = hash_stream(stream, stop)
        if offset > size or (offset == size and digest.hexdigest() != md5):
            stream.seek(0)
            stream.truncate()
            offset, digest = 0, digest_new()
        if offset == size and digest.hexdigest() == md5:
            stream.flush()
            os.fsync(stream.fileno())
        else:
            check_stop(stop)
            url = api.download_url(remote)  # Fresh signed URL on every retry.
            headers = {"Accept-Encoding": "identity"}
            if offset:
                headers["Range"] = "bytes=%d-" % offset
            # Separate session: OAuth must never be sent to signed URLs.
            with requests.Session() as session:
                with session.get(url, headers=headers, stream=True, timeout=timeout) as response:
                    check_stop(stop)
                    if response.status_code == 206:
                        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)",
                                             response.headers.get("Content-Range", ""))
                        if (not match or int(match[1]) != offset or int(match[3]) != size
                                or int(match[2]) != size - 1):
                            raise BackupError("invalid Content-Range; partial preserved")
                    elif response.status_code == 200:
                        stream.seek(0)
                        stream.truncate()
                        offset, digest = 0, digest_new()
                    else:
                        raise BackupError("download HTTP %d" % response.status_code)
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise BackupError("unexpected encoded download response")
                    length_header = response.headers.get("Content-Length")
                    if length_header is not None and length_header != str(size - offset):
                        raise BackupError("download Content-Length mismatch")
                    stream.seek(offset)
                    for chunk in response.iter_content(CHUNK):
                        check_stop(stop)
                        if not chunk:
                            continue
                        if offset + len(chunk) > size:
                            raise BackupError("download exceeds manifest size")
                        stream.write(chunk)
                        digest.update(chunk)
                        offset += len(chunk)
                        progress.add(len(chunk))
                    check_stop(stop)
                    if offset != size:
                        raise BackupError("download size mismatch")
                    if digest.hexdigest() != md5:
                        # Bad partial cannot be resumed; keep it until retry,
                        # which detects a full-sized invalid MD5 and restarts.
                        raise BackupError("download MD5 mismatch")
                    stream.flush()
                    os.fsync(stream.fileno())
    publish(part, final, size, md5, stop)
    return "DOWNLOADED"


def worker(auth, row, root, stop, timeout, attempts, progress):
    api = YandexAPI(auth, stop, timeout)
    try:
        for attempt in range(1, attempts + 1):
            try:
                check_stop(stop)
                return transfer(api, row, root, stop, timeout, progress), None
            except Stopped:
                return "INTERRUPTED", None
            except Exception as exc:
                if stop.is_set():
                    return "INTERRUPTED", None
                error = safe_error(exc)
                if attempt == attempts:
                    return "FAILED", error
                delay = min(2 ** attempt, 30)
                LOG.warning("RETRY %r (%d/%d): %s; waiting %ds",
                            row["path"], attempt, attempts, error, delay)
                if stop.wait(delay):
                    return "INTERRUPTED", None
    finally:
        api.close()


def run(db, root, auth, stop, timeout, workers=4, order="asc", attempts=3,
        progress_interval=30, skip_failed=False):
    direction = {"asc": "ASC", "desc": "DESC"}[order]
    # Only the coordinator touches SQLite. In-memory metadata for ~90K rows
    # is modest; at most `workers` futures exist at any time.
    excluded = ("verified", "failed") if skip_failed else ("verified",)
    placeholders = ",".join("?" for _ in excluded)
    rows = [dict(row) for row in db.execute(
        "SELECT path,size,md5 FROM files WHERE status IS NULL OR status NOT IN ("
        + placeholders + ") ORDER BY size " + direction + ",path ASC", excluded)]
    all_paths = {row[0] for row in db.execute("SELECT path FROM files")}
    count, size = db.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM files").fetchone()
    LOG.info("Manifest: %d files, %.3f TB; queued: %d; workers: %d; order: %s",
             count, size / 1e12, len(rows), workers, order)
    if skip_failed:
        skipped = db.execute("SELECT COUNT(*) FROM files WHERE status='failed'").fetchone()[0]
        LOG.info("Skipping %d failed files for this run; their status is unchanged", skipped)
    progress = Progress()
    iterator = iter(rows)
    completed = failed = interrupted = 0
    started = last_report = time.monotonic()
    last_bytes = 0
    api = YandexAPI(auth, stop, timeout)
    futures = {}
    pool = ThreadPoolExecutor(max_workers=workers)
    exhausted = False
    stopping_logged = False
    try:
        while futures or not exhausted:
            if stop.is_set():
                exhausted = True
                if not stopping_logged:
                    LOG.info("Stopping: no new tasks; waiting for active I/O to return")
                    stopping_logged = True
                for future in futures:
                    future.cancel()
            while not stop.is_set() and not exhausted and len(futures) < workers:
                row = next(iterator, None)
                if row is None:
                    exhausted = True
                    break
                try:
                    # A real remote file ending in .ydb-part must never be
                    # mistaken for another file's temporary download.
                    if row["path"] + ".ydb-part" in all_paths:
                        raise BackupError("partial filename collides with a manifest file")
                    if not row["md5"]:
                        meta = None
                        for attempt in range(attempts):
                            try:
                                meta = api.get("/resources", path=row["path"])
                                break
                            except Stopped:
                                raise
                            except Exception:
                                if attempt + 1 == attempts:
                                    raise
                                if stop.wait(min(2 ** (attempt + 1), 30)):
                                    raise Stopped()
                        md5 = meta.get("md5", "")
                        if (meta.get("size") != row["size"] or meta.get("type") != "file"
                                or not isinstance(md5, str)
                                or not re.fullmatch(r"[0-9a-fA-F]{32}", md5)):
                            raise BackupError("remote metadata changed or has no MD5; scan required")
                        with db:
                            db.execute("UPDATE files SET md5=? WHERE path=?", (md5, row["path"]))
                        row["md5"] = md5
                    check_stop(stop)
                    future = pool.submit(worker, auth, row, root, stop, timeout, attempts, progress)
                    futures[future] = row
                except Stopped:
                    break
                except Exception as exc:
                    error = safe_error(exc)
                    with db:
                        db.execute("UPDATE files SET status='failed',error=? WHERE path=?",
                                   (error, row["path"]))
                    LOG.error("FAILED %r: %s", row["path"], error)
                    failed += 1
                    completed += 1
            done, _ = wait(futures, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in done:
                row = futures.pop(future)
                if future.cancelled():
                    outcome, error = "INTERRUPTED", None
                else:
                    try:
                        outcome, error = future.result()
                    except Exception as exc:
                        outcome, error = "FAILED", safe_error(exc)
                if outcome in ("EXISTING", "DOWNLOADED"):
                    # transfer returned only after full validation and durable
                    # publication. A subsequent signal cannot invalidate success.
                    with db:
                        db.execute("UPDATE files SET status='verified',error=NULL WHERE path=?",
                                   (row["path"],))
                    LOG.info("%s %r | %.3f GB | size + MD5 OK",
                             outcome, row["path"], row["size"] / 1e9)
                elif outcome == "FAILED":
                    failed += 1
                    with db:
                        db.execute("UPDATE files SET status='failed',error=? WHERE path=?",
                                   (error, row["path"]))
                    LOG.error("FAILED %r: %s", row["path"], error)
                else:
                    interrupted += 1
                completed += 1
            now = time.monotonic()
            if now - last_report >= progress_interval:
                transferred = progress.read()
                LOG.info("PROGRESS completed=%d/%d failed=%d active=%d; received=%.3f GB; %.2f MB/s",
                         completed, len(rows), failed, len(futures), transferred / 1e9,
                         (transferred - last_bytes) / (now - last_report) / 1e6)
                last_report, last_bytes = now, transferred
        LOG.info("Finished: completed=%d/%d failed=%d interrupted=%d; elapsed=%.1fs",
                 completed, len(rows), failed, interrupted, time.monotonic() - started)
        return failed
    finally:
        # Also stop workers if coordinator/SQLite fails. Never release process
        # locks before all workers have stopped touching destination files.
        if futures:
            stop.set()
        pool.shutdown(wait=True, cancel_futures=True)
        api.close()


if __name__ == "__main__":
    print("Run: python3 backup.py download --help")

