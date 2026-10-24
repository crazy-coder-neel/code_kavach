"""Controlled SAFE placeholder.

The organizer-provided safe/unsafe pair has not been supplied yet. Until it is,
this clearly-marked placeholder is the only "safe" snippet the demo executes.
It performs one harmless side effect: it writes a marker file whose path is
passed as argv[1]. It touches no network, no credentials and no other file.
"""
import sys
from pathlib import Path

if len(sys.argv) > 1:
    Path(sys.argv[1]).write_text("safe-placeholder-ran", encoding="utf-8")
print("safe placeholder executed")
