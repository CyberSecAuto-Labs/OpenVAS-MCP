"""Entry point: python -m openvas_mcp"""

import asyncio
import sys

from .auth import APIKeyStore, AuthMiddleware
from .config import cfg
from .logging_config import apply_json_formatter
from .policy import load_policy, set_policy
from .server import KNOWN_TOOLS, mcp


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

    apply_json_formatter(cfg.log_level)

    import logging as _logging

    if cfg.username == "admin":
        _logging.getLogger(__name__).warning(
            "GVM_USERNAME is set to the default 'admin'; "
            "consider creating a dedicated GVM user with least privilege"
        )

    try:
        policy = load_policy(cfg.mcp_policy_file, known_tools=KNOWN_TOOLS)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    set_policy(policy)

    if cfg.mcp_allow_unauthenticated and cfg.mcp_policy_file:
        _logging.getLogger(__name__).warning(
            "MCP_ALLOW_UNAUTHENTICATED=1 is set with a policy file (%s); "
            "all requests will be evaluated as the default policy identity (no client_id). "
            "Named client entries in the policy will never be matched.",
            cfg.mcp_policy_file,
        )

    if cfg.mcp_transport == "stdio":
        mcp.run("stdio")
        return

    import logging

    import uvicorn

    if cfg.mcp_transport == "sse":
        base_app = mcp.sse_app()
    else:
        base_app = mcp.streamable_http_app()

    key_store = APIKeyStore(cfg.mcp_api_keys)
    if key_store.is_empty:
        if not cfg.mcp_allow_unauthenticated:
            print(
                "ERROR: HTTP transport requires MCP_API_KEYS to be set.\n"
                "       Set MCP_ALLOW_UNAUTHENTICATED=1 to explicitly run without authentication."
            )
            sys.exit(1)
        logging.getLogger(__name__).warning(
            "HTTP transport running without authentication (MCP_ALLOW_UNAUTHENTICATED=1)"
        )
        app = base_app
    else:
        app = AuthMiddleware(base_app, key_store=key_store)  # type: ignore[assignment]

    async def _serve() -> None:
        config = uvicorn.Config(app, host=cfg.mcp_host, port=cfg.mcp_port)
        server = uvicorn.Server(config)
        await server.serve()

    asyncio.run(_serve())


if __name__ == "__main__":
    main()
