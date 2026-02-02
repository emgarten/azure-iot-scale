import logging
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import gevent
import orjson
import yaml

logger = logging.getLogger("locust.utils")


class LazyConfig:
    """Lazily loads and caches environment variables on first access.

    Falls back to testenv.yaml if environment variables are not set.
    """

    _yaml_config: dict[str, str] | None = None

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}

    @classmethod
    def _load_yaml_config(cls) -> dict[str, str]:
        """Load testenv.yaml from the same directory as utils.py.

        Returns:
            Dict mapping variable names to values, or empty dict if file doesn't exist.
        """
        if cls._yaml_config is not None:
            return cls._yaml_config

        config_path = Path(__file__).parent / "testenv.yaml"
        if not config_path.exists():
            cls._yaml_config = {}
            return cls._yaml_config

        with open(config_path) as f:
            data = yaml.safe_load(f)

        cls._yaml_config = {}
        if data and "env" in data:
            for item in data["env"]:
                if "name" in item and "value" in item:
                    cls._yaml_config[item["name"]] = str(item["value"])

        return cls._yaml_config

    def _require_env(self, name: str) -> str:
        """Get required environment variable, falling back to config.yaml.

        Args:
            name: The name of the environment variable.

        Returns:
            The value of the environment variable.

        Raises:
            ValueError: If the environment variable is not set and not in config.yaml.
        """
        value = os.getenv(name)
        if value is not None:
            return value

        yaml_config = self._load_yaml_config()
        if name in yaml_config:
            return yaml_config[name]

        raise ValueError(f"Required environment variable {name} is not set")

    def get(self, name: str) -> str:
        """Get a required env var, caching the result."""
        if name not in self._cache:
            self._cache[name] = self._require_env(name)
        return self._cache[name]

    def get_int(self, name: str) -> int:
        """Get a required env var as an integer."""
        return int(self.get(name))

    def get_bool(self, name: str) -> bool:
        """Get a required env var as a boolean (true/false string)."""
        return self.get(name).lower() == "true"

    def get_optional(self, name: str) -> str | None:
        """Get an optional env var, returning None if not set."""
        if name not in self._cache:
            value = os.getenv(name)
            if value is None:
                yaml_config = self._load_yaml_config()
                value = yaml_config.get(name)
            if value is not None:
                self._cache[name] = value
            else:
                return None
        return self._cache.get(name)


config = LazyConfig()


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
