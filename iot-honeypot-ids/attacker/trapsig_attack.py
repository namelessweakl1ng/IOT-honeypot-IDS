#!/usr/bin/env python3
"""TRAPSIG Attack Simulator — CLI entry point.

Usage:
  python3 trapsig_attack.py list
  python3 trapsig_attack.py validate --config config.yaml
  python3 trapsig_attack.py recon_basic --config config.yaml --dry-run
  python3 trapsig_attack.py multi_stage --config config.yaml --seed 12345 --yes

This is the entry point for Computer 2 (the attacker machine).
It does NOT require TRAPSIG backend availability — it only generates
network traffic against the configured Raspberry Pi honeypot.
"""
import sys
import os

# Add this directory to sys.path so `sim` package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sim import main

if __name__ == "__main__":
    sys.exit(main())
