#!/usr/bin/env python3

import argparse
import glob
import os
import shutil
import sys
import zipfile
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT, "src")
DIST_DIR = os.path.join(ROOT, "dist")
BACKUP_DIR = os.path.join(ROOT, ".backups")
DIST_BINARY = os.path.join(DIST_DIR, "nft-firewall")
MAX_BACKUPS = 5


def backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = os.path.join(BACKUP_DIR, f"src_backup_{timestamp}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in glob.glob(os.path.join(SRC_DIR, "**"), recursive=True):
            if os.path.isfile(fpath):
                arcname = os.path.relpath(fpath, ROOT)
                zf.write(fpath, arcname)
    print(f"Backup saved: {zip_path}")
    _prune_backups()


def _prune_backups():
    zips = sorted(glob.glob(os.path.join(BACKUP_DIR, "src_backup_*.zip")))
    for old in zips[:-MAX_BACKUPS]:
        os.remove(old)
        print(f"Deleted old backup: {old}")


def build():
    os.makedirs(DIST_DIR, exist_ok=True)
    print("Building...")
    shutil.copy(os.path.join(SRC_DIR, "main.py"), DIST_BINARY)
    os.chmod(DIST_BINARY, 0o755)
    print(f"Binary ready: {DIST_BINARY}")


def undo():
    zips = sorted(glob.glob(os.path.join(BACKUP_DIR, "src_backup_*.zip")))
    if not zips:
        print("Error: No backups found.")
        sys.exit(1)
    latest = zips[-1]
    print(f"Restoring from: {latest}")
    shutil.rmtree(SRC_DIR)
    os.makedirs(SRC_DIR, exist_ok=True)
    with zipfile.ZipFile(latest, "r") as zf:
        zf.extractall(ROOT)
    build()
    print("Reverted to previous state!")


def main():
    parser = argparse.ArgumentParser(description="Time Machine build script")
    parser.add_argument("--undo", action="store_true", help="Restore src/ from the most recent backup and rebuild")
    args = parser.parse_args()

    if args.undo:
        undo()
    else:
        backup()
        build()


if __name__ == "__main__":
    main()
