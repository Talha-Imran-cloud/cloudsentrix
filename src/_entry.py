"""Entry point for pip-installed cloudsentrix command."""
import os
import sys

# Add cloudsentrix package directory to path
# This makes all sibling modules (parser, graph, etc.) importable
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from cli import main

if __name__ == "__main__":
    sys.exit(main())
