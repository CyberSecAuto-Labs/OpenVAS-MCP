"""Entry point: python -m openvas_mcp"""

import sys

from .config import cfg
from .server import mcp


def main():
    try:
        missing = cfg.missing_required()
    except ValueError as e:
        print(f"ERROR: Invalid configuration: {e}")
        sys.exit(1)

    if missing:
        print("ERROR: Missing required environment variables:")
        for m in missing:
            print(f"  - {m}")
        sys.exit(1)

    mcp.run()


if __name__ == "__main__":
    main()
