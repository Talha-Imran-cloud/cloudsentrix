"""Entry point for pip-installed cloudsentrix command."""
import os, sys

# Add the package directory to path so all modules are importable
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from cli import main

if __name__ == "__main__":
    main()
