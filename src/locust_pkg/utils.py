import logging
import random
import time
from datetime import datetime, timezone
from typing import Any, Callable

import orjson

logger = logging.getLogger("locust.utils")


# Create a message of the given size with the current UTC timestamp
def create_msg(size: int, now: str | None = None) -> bytes:
    if now is None:
        now = datetime.now(tz=timezone.utc).isoformat() + "Z"
    message = orjson.dumps({"date": now, "val": "A" * size})
    return message


def x509_certificate_list_to_pem(cert_list: list[str]) -> str:
    """Convert a list of base64-encoded certificates to PEM format.

    Args:
        cert_list: List of base64-encoded certificate strings

    Returns:
        A PEM-formatted string containing all certificates
    """
    begin_cert_header = "-----BEGIN CERTIFICATE-----\r\n"
    end_cert_footer = "\r\n-----END CERTIFICATE-----"
    separator = end_cert_footer + "\r\n" + begin_cert_header
    return begin_cert_header + separator.join(cert_list) + end_cert_footer


def retry_with_backoff(
    operation_name: str,
    operation_func: Callable[[], Any],
    base_wait: int = 60,
    max_jitter: int = 30,
) -> Any:
    """Retry an operation indefinitely with exponential backoff and jitter.

    Args:
        operation_name: Name of the operation for logging
        operation_func: Function to execute (should return a value or raise exception)
        base_wait: Base wait time in seconds between retries (default: 60)
        max_jitter: Maximum random jitter in seconds to add to wait time (default: 30)

    Returns:
        The result of operation_func when it succeeds
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            result = operation_func()
            if attempt > 1:
                logger.info(f"{operation_name} succeeded on attempt {attempt}")
            return result
        except Exception as e:
            jitter = random.uniform(0, max_jitter)
            wait_time = base_wait + jitter
            logger.warning(f"{operation_name} failed (attempt {attempt}): {e}")
            logger.info(f"Retrying {operation_name} in {wait_time:.1f}s...")
            time.sleep(wait_time)
