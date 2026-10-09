"""Convenient application entry point: python main.py."""

import asyncio
import logging

from main_bot import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Shutdown requested")
    except Exception as exc:
        logging.getLogger(__name__).error(
            "Startup failed: %s. Check configuration and connectivity.", type(exc).__name__
        )
        raise SystemExit(1) from None
