import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Any, Callable

import gevent
import orjson

logger = logging.getLogger("locust.utils")


def log_all_env_vars() -> None:
    """Log all environment variables (sorted) for debugging."""
    logger.info("All environment variables:")
    for key, value in sorted(os.environ.items()):
        logger.info(f"  {key}={value}")


def require_env(name: str) -> str:
    """Get required environment variable, raising if not set.

    Args:
        name: The name of the environment variable.

    Returns:
        The value of the environment variable.

    Raises:
        ValueError: If the environment variable is not set.
    """
    value = os.getenv(name)
    if value is None:
        raise ValueError(f"Required environment variable {name} is not set")
    return value


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


def parse_request_id_from_topic(topic: str) -> str | None:
    """Parse the request ID ($rid) from an IoT Hub MQTT topic.

    Extracts the $rid parameter from topics like:
    - $iothub/credentials/res/202/?$rid=66641568
    - $iothub/credentials/res/200/?$rid=550e8400-e29b-41d4-a716-446655440000&$version=1

    Args:
        topic: MQTT topic string

    Returns:
        The request ID as a string, or None if not found.
    """
    parts = topic.split("/")
    if len(parts) < 5:
        return None

    query_part = parts[4]  # e.g., "?$rid=550e8400-e29b-41d4-a716-446655440000&$version=1"
    if query_part.startswith("?"):
        query_part = query_part[1:]

    for param in query_part.split("&"):
        if param.startswith("$rid="):
            rid_value = param[5:]
            return rid_value if rid_value else None

    return None


def retry_with_backoff(
    operation_name: str,
    operation_func: Callable[[], Any],
    base_wait: int = 60,
    max_jitter: int = 30,
    max_timeout: float | None = None,
    max_attempts: int | None = None,
) -> Any:
    """Retry an operation with backoff and jitter, optionally with a timeout or max attempts.

    Args:
        operation_name: Name of the operation for logging
        operation_func: Function to execute (should return a value or raise exception)
        base_wait: Base wait time in seconds between retries (default: 60)
        max_jitter: Maximum random jitter in seconds to add to wait time (default: 30)
        max_timeout: Maximum total time in seconds before giving up (default: None = no timeout)
        max_attempts: Maximum number of attempts before giving up (default: None = no limit)

    Returns:
        The result of operation_func when it succeeds

    Raises:
        TimeoutError: If max_timeout is reached before the operation succeeds
        Exception: If max_attempts is reached before the operation succeeds (re-raises last exception)
    """
    attempt = 0
    start_time = time.time()
    while True:
        attempt += 1
        try:
            result = operation_func()
            if attempt > 1:
                logger.info(f"{operation_name} succeeded on attempt {attempt}")
            return result
        except Exception as e:
            elapsed = time.time() - start_time

            # Check if we've exceeded max attempts
            if max_attempts is not None and attempt >= max_attempts:
                logger.warning(f"{operation_name} failed after {attempt} attempts")
                raise

            jitter = random.uniform(0, max_jitter)
            wait_time = base_wait + jitter

            # Check if we would exceed the timeout after waiting
            if max_timeout is not None and (elapsed + wait_time) >= max_timeout:
                logger.warning(f"{operation_name} timed out after {elapsed:.1f}s ({attempt} attempts)")
                raise TimeoutError(f"{operation_name} timed out after {elapsed:.1f}s ({attempt} attempts)") from e

            logger.warning(f"{operation_name} failed (attempt {attempt}): {e}")
            logger.info(f"Retrying {operation_name} in {wait_time:.1f}s...")
            gevent.sleep(wait_time)
