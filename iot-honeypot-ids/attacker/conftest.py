"""pytest configuration — makes attacker/sim importable from repo root."""
import sys
from pathlib import Path

attacker_dir = Path(__file__).resolve().parent
if str(attacker_dir) not in sys.path:
    sys.path.insert(0, str(attacker_dir))
