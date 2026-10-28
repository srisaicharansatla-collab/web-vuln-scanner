#!/usr/bin/env python3
"""Entry point:  python scanner.py http://localhost:3000 --i-have-permission -o report.json"""
import sys

from vulnscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
