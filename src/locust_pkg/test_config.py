import logging
import os
from pathlib import Path

import yaml

logger = logging.getLogger("locust.test_config")


class TestConfig:
    """Lazily loads and caches environment variables on first access.

    Falls back to testenv.yaml if environment variables are not set.
    Logs the value of each key the first time it is read.
    """

    _yaml_config: dict[str, str] | None = None

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}
        self._logged_keys: set[str] = set()

    @classmethod
    def _load_yaml_config(cls) -> dict[str, str]:
        """Load config YAML, checking SCALE_CONFIG_PATH env var first.

        If SCALE_CONFIG_PATH is set and the file exists, loads from that path.
        Otherwise falls back to testenv.yaml in the same directory as test_config.py.

        Returns:
            Dict mapping variable names to values, or empty dict if file doesn't exist.
        """
        if cls._yaml_config is not None:
            return cls._yaml_config

        config_path: Path | None = None
        custom_path = os.getenv("SCALE_CONFIG_PATH")
        if custom_path:
            custom_config_path = Path(custom_path)
            if custom_config_path.exists():
                config_path = custom_config_path
                logger.info(f"Using config from SCALE_CONFIG_PATH: {config_path}")
            else:
                logger.warning(f"SCALE_CONFIG_PATH set but file not found: {custom_path}")

        if config_path is None:
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

    def _log_first_access(self, name: str, value: str | None, log_value: bool) -> None:
        """Log the value of a key the first time it is read.

        Args:
            name: The name of the environment variable.
            value: The value of the environment variable.
            log_value: If True, log the actual value. If False, log 'set' or 'unset'.
        """
        if name in self._logged_keys:
            return
        self._logged_keys.add(name)

        if log_value:
            display_value = value if value is not None else "unset"
        else:
            display_value = "set" if value is not None else "unset"

        logger.info(f"Config {name}: {display_value}")

    def get(self, name: str, *, log_value: bool = True) -> str:
        """Get a required env var, caching the result.

        Args:
            name: The name of the environment variable.
            log_value: If True, log the actual value on first read. If False, log 'set' or 'unset'.

        Returns:
            The value of the environment variable.
        """
        if name not in self._cache:
            self._cache[name] = self._require_env(name)
        self._log_first_access(name, self._cache[name], log_value)
        return self._cache[name]

    def get_int(self, name: str, *, log_value: bool = True) -> int:
        """Get a required env var as an integer.

        Args:
            name: The name of the environment variable.
            log_value: If True, log the actual value on first read. If False, log 'set' or 'unset'.

        Returns:
            The value as an integer.
        """
        return int(self.get(name, log_value=log_value))

    def get_bool(self, name: str, *, log_value: bool = True) -> bool:
        """Get a required env var as a boolean (true/false string).

        Args:
            name: The name of the environment variable.
            log_value: If True, log the actual value on first read. If False, log 'set' or 'unset'.

        Returns:
            True if the value is 'true' (case-insensitive), False otherwise.
        """
        return self.get(name, log_value=log_value).lower() == "true"

    def get_optional(self, name: str, *, log_value: bool = True) -> str | None:
        """Get an optional env var, returning None if not set.

        Args:
            name: The name of the environment variable.
            log_value: If True, log the actual value on first read. If False, log 'set' or 'unset'.

        Returns:
            The value of the environment variable, or None if not set.
        """
        if name not in self._cache:
            value = os.getenv(name)
            if value is None:
                yaml_config = self._load_yaml_config()
                value = yaml_config.get(name)
            if value is not None:
                self._cache[name] = value

        result = self._cache.get(name)
        self._log_first_access(name, result, log_value)
        return result


config = TestConfig()
