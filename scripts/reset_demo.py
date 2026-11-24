"""Reset only this repository's fixed local SQLite demo file. Stop the server first."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--confirm-synthetic-reset", action="store_true", required=True)
parser.parse_args()
root = Path(__file__).resolve().parent.parent
target = root / "sentinelforge.db"
if target.is_symlink() or target.resolve().parent != root:
    raise SystemExit("Refusing unexpected database path")
if target.exists():
    target.unlink()
print("Local synthetic database reset; restart to reseed.")
