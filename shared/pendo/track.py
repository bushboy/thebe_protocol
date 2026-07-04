"""Server-side Pendo Track Event utility.

Sends track events to the Pendo data API via HTTP POST.
Failures are logged but never propagate to callers.
"""

import time
import httpx
from typing import Any, Dict, Optional

from shared.logging import JSONLogger

logger = JSONLogger(__name__)

PENDO_DATA_HOST = "https://data.pendo.io"
PENDO_INTEGRATION_KEY = "298fd271-7eeb-488e-8dc2-ff8e9f5aa4cf"
PENDO_TRACK_URL = f"{PENDO_DATA_HOST}/data/track"
PENDO_TIMEOUT = 5.0


async def track_event(
    event: str,
    visitor_id: str = "system",
    account_id: str = "system",
    properties: Optional[Dict[str, Any]] = None,
) -> None:
    """Send a server-side Pendo track event.

    Args:
        event: Descriptive event name.
        visitor_id: Unique user identifier. Use "system" only when
                    no user context is available.
        account_id: Unique account identifier. Use "system" only when
                    no account context is available.
        properties: Optional metadata dict for the event.
    """
    payload = {
        "type": "track",
        "event": event,
        "visitorId": visitor_id,
        "accountId": account_id,
        "timestamp": int(time.time() * 1000),
    }
    if properties:
        payload["properties"] = properties

    try:
        async with httpx.AsyncClient(timeout=PENDO_TIMEOUT) as client:
            await client.post(
                PENDO_TRACK_URL,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-pendo-integration-key": PENDO_INTEGRATION_KEY,
                },
            )
    except Exception as exc:
        logger.warning(f"Pendo track event failed for '{event}': {exc}")
