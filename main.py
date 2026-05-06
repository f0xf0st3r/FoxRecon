"""FoxRecon - Main entry point."""

from __future__ import annotations

import uvicorn

from internal.api.app import create_app
from internal.config import get_settings


def main() -> None:
    """Start the FoxRecon API server."""
    settings = get_settings()
    app = create_app()

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        workers=1,  # Use gunicorn for production multi-worker
        log_level="debug" if settings.debug else "info",
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
