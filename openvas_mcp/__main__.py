"""Entry point: python -m openvas_mcp"""

from .gvm_client import require_env
from .server import mcp


def main():
    missing = require_env()
    if missing:
        import sys

        print("ERROR: Missing required environment variables:")
        for m in missing:
            print(f"  - {m}")
        sys.exit(1)
    mcp.run()


if __name__ == "__main__":
    main()
