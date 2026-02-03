"""Tests for utils.py module."""

import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import orjson
import pytest

from locust_pkg.test_config import TestConfig
from locust_pkg.utils import create_msg, parse_request_id_from_topic, x509_certificate_list_to_pem


class TestCreateMsg:
    """Tests for the create_msg function."""

    def test_create_msg_with_default_now(self) -> None:
        """Test create_msg generates a message with current timestamp when now is not provided."""
        size = 10
        message = create_msg(size)

        # Verify the message is bytes
        assert isinstance(message, bytes)

        # Parse the message
        parsed = orjson.loads(message)

        # Verify structure
        assert "date" in parsed
        assert "val" in parsed

        # Verify the value has the correct size
        assert len(parsed["val"]) == size
        assert parsed["val"] == "A" * size

        # Verify the date format is valid ISO 8601 with Z suffix
        assert parsed["date"].endswith("Z")

        # Verify we can parse the timestamp (validates ISO format)
        timestamp_str = parsed["date"].rstrip("Z")
        parsed_time = datetime.fromisoformat(timestamp_str)
        assert parsed_time.tzinfo == timezone.utc

    def test_create_msg_with_custom_now(self) -> None:
        """Test create_msg uses the provided now parameter."""
        size = 5
        custom_time = "2024-01-15T10:30:45.123456+00:00Z"
        message = create_msg(size, now=custom_time)

        # Parse the message
        parsed = orjson.loads(message)

        # Verify the custom timestamp is used
        assert parsed["date"] == custom_time
        assert parsed["val"] == "A" * size

    def test_create_msg_with_zero_size(self) -> None:
        """Test create_msg with zero size creates an empty value."""
        message = create_msg(0)
        parsed = orjson.loads(message)

        assert parsed["val"] == ""
        assert "date" in parsed

    def test_create_msg_with_large_size(self) -> None:
        """Test create_msg with a large size value."""
        size = 1000
        message = create_msg(size)
        parsed = orjson.loads(message)

        assert len(parsed["val"]) == size
        assert parsed["val"] == "A" * size

    def test_create_msg_with_various_sizes(self) -> None:
        """Test create_msg with various size values."""
        sizes = [1, 10, 50, 100, 500]

        for size in sizes:
            message = create_msg(size)
            parsed = orjson.loads(message)
            assert len(parsed["val"]) == size
            assert parsed["val"] == "A" * size

    def test_create_msg_now_parameter_is_optional(self) -> None:
        """Test that the now parameter is truly optional."""
        # Should work without the now parameter
        message1 = create_msg(10)
        assert isinstance(message1, bytes)

        # Should work with the now parameter
        message2 = create_msg(10, now="2024-01-01T00:00:00+00:00Z")
        assert isinstance(message2, bytes)

        parsed1 = orjson.loads(message1)
        parsed2 = orjson.loads(message2)

        # The timestamps should be different
        assert parsed1["date"] != parsed2["date"]
        assert parsed2["date"] == "2024-01-01T00:00:00+00:00Z"

    def test_create_msg_timestamp_format(self) -> None:
        """Test that the automatically generated timestamp has the correct format."""
        message = create_msg(5)
        parsed = orjson.loads(message)

        timestamp = parsed["date"]

        # Should end with Z
        assert timestamp.endswith("Z")

        # Should be parseable as ISO format
        timestamp_str = timestamp.rstrip("Z")
        dt = datetime.fromisoformat(timestamp_str)

        # Should be recent (within the last minute)
        now = datetime.now(tz=timezone.utc)
        time_diff = abs((now - dt).total_seconds())
        assert time_diff < 60  # Should be within 60 seconds

    def test_create_msg_json_structure(self) -> None:
        """Test that the message has the correct JSON structure."""
        custom_time = "2024-06-15T12:00:00+00:00Z"
        message = create_msg(20, now=custom_time)
        parsed = orjson.loads(message)

        # Should have exactly 2 keys
        assert len(parsed) == 2
        assert set(parsed.keys()) == {"date", "val"}

        # Values should be strings
        assert isinstance(parsed["date"], str)
        assert isinstance(parsed["val"], str)

    def test_create_msg_returns_bytes(self) -> None:
        """Test that create_msg always returns bytes."""
        message1 = create_msg(10)
        message2 = create_msg(10, now="2024-01-01T00:00:00+00:00Z")

        assert isinstance(message1, bytes)
        assert isinstance(message2, bytes)


class TestX509CertificateListToPem:
    """Tests for the x509_certificate_list_to_pem function."""

    def test_single_certificate(self) -> None:
        """Test converting a single certificate to PEM format."""
        cert_list = ["MIIB1zCCAX2gAwIBAgIQJTSME"]

        result = x509_certificate_list_to_pem(cert_list)

        expected = "-----BEGIN CERTIFICATE-----\r\n" "MIIB1zCCAX2gAwIBAgIQJTSME" "\r\n-----END CERTIFICATE-----"
        assert result == expected

    def test_multiple_certificates(self) -> None:
        """Test converting multiple certificates to PEM format."""
        cert_list = ["MIIB1zCCAX2gAwIBAgIQJTSME", "MIIC2DCCAcCgAwIBAgIRAKhZ", "MIIDGzCCAgOgAwIBAgIQemQ"]

        result = x509_certificate_list_to_pem(cert_list)

        expected = (
            "-----BEGIN CERTIFICATE-----\r\n"
            "MIIB1zCCAX2gAwIBAgIQJTSME"
            "\r\n-----END CERTIFICATE-----\r\n"
            "-----BEGIN CERTIFICATE-----\r\n"
            "MIIC2DCCAcCgAwIBAgIRAKhZ"
            "\r\n-----END CERTIFICATE-----\r\n"
            "-----BEGIN CERTIFICATE-----\r\n"
            "MIIDGzCCAgOgAwIBAgIQemQ"
            "\r\n-----END CERTIFICATE-----"
        )
        assert result == expected

    def test_empty_list(self) -> None:
        """Test with an empty certificate list."""
        cert_list: list[str] = []

        result = x509_certificate_list_to_pem(cert_list)

        expected = "-----BEGIN CERTIFICATE-----\r\n\r\n-----END CERTIFICATE-----"
        assert result == expected

    def test_pem_format_structure(self) -> None:
        """Test that the output has proper PEM format structure."""
        cert_list = ["TESTCERT123"]

        result = x509_certificate_list_to_pem(cert_list)

        # Should start with BEGIN CERTIFICATE
        assert result.startswith("-----BEGIN CERTIFICATE-----\r\n")
        # Should end with END CERTIFICATE
        assert result.endswith("\r\n-----END CERTIFICATE-----")
        # Should contain the certificate data
        assert "TESTCERT123" in result

    def test_certificate_chain(self) -> None:
        """Test converting a certificate chain (leaf, intermediate, root)."""
        cert_list = ["LeafCertificateDataHere", "IntermediateCertificateDataHere", "RootCertificateDataHere"]

        result = x509_certificate_list_to_pem(cert_list)

        # Verify all certificates are present
        assert "LeafCertificateDataHere" in result
        assert "IntermediateCertificateDataHere" in result
        assert "RootCertificateDataHere" in result

        # Verify proper separation between certificates
        assert result.count("-----BEGIN CERTIFICATE-----") == 3
        assert result.count("-----END CERTIFICATE-----") == 3

    def test_preserves_certificate_order(self) -> None:
        """Test that the function preserves the order of certificates."""
        cert_list = ["FIRST", "SECOND", "THIRD"]

        result = x509_certificate_list_to_pem(cert_list)

        # Find positions of each certificate
        first_pos = result.find("FIRST")
        second_pos = result.find("SECOND")
        third_pos = result.find("THIRD")

        # Verify order is preserved
        assert first_pos < second_pos < third_pos

    def test_realistic_base64_certificate(self) -> None:
        """Test with a realistic-looking base64 encoded certificate."""
        # This is a truncated example of what a real base64 cert looks like
        cert_list = ["MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ"]

        result = x509_certificate_list_to_pem(cert_list)

        expected = (
            "-----BEGIN CERTIFICATE-----\r\n"
            "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ"
            "\r\n-----END CERTIFICATE-----"
        )
        assert result == expected

    def test_windows_line_endings(self) -> None:
        """Test that the function uses Windows-style line endings (\\r\\n)."""
        cert_list = ["CERT1", "CERT2"]

        result = x509_certificate_list_to_pem(cert_list)

        # Should use \r\n not just \n
        assert "\r\n" in result
        # Should not have Unix-style line endings alone
        assert result.replace("\r\n", "") == result.replace("\n", "").replace("\r", "")


class TestParseRequestIdFromTopic:
    """Tests for the parse_request_id_from_topic function."""

    def test_valid_topic_with_rid(self) -> None:
        """Test parsing a valid topic with $rid parameter."""
        topic = "$iothub/credentials/res/202/?$rid=66641568"
        result = parse_request_id_from_topic(topic)
        assert result == "66641568"

    def test_valid_topic_with_rid_and_version(self) -> None:
        """Test parsing a topic with $rid and other parameters."""
        topic = "$iothub/credentials/res/200/?$rid=12345&$version=1"
        result = parse_request_id_from_topic(topic)
        assert result == "12345"

    def test_topic_with_rid_not_first_param(self) -> None:
        """Test parsing when $rid is not the first query parameter."""
        topic = "$iothub/credentials/res/200/?$version=1&$rid=99999"
        result = parse_request_id_from_topic(topic)
        assert result == "99999"

    def test_topic_without_rid(self) -> None:
        """Test parsing a topic without $rid parameter."""
        topic = "$iothub/credentials/res/202/?$version=1"
        result = parse_request_id_from_topic(topic)
        assert result is None

    def test_topic_with_empty_query_string(self) -> None:
        """Test parsing a topic with empty query string."""
        topic = "$iothub/credentials/res/202/?"
        result = parse_request_id_from_topic(topic)
        assert result is None

    def test_topic_without_query_string(self) -> None:
        """Test parsing a topic without query string."""
        topic = "$iothub/credentials/res/202"
        result = parse_request_id_from_topic(topic)
        assert result is None

    def test_topic_with_uuid_rid_value(self) -> None:
        """Test parsing a topic with UUID $rid value."""
        topic = "$iothub/credentials/res/202/?$rid=550e8400-e29b-41d4-a716-446655440000"
        result = parse_request_id_from_topic(topic)
        assert result == "550e8400-e29b-41d4-a716-446655440000"

    def test_topic_with_empty_rid_value(self) -> None:
        """Test parsing a topic with empty $rid value."""
        topic = "$iothub/credentials/res/202/?$rid="
        result = parse_request_id_from_topic(topic)
        assert result is None

    def test_short_topic(self) -> None:
        """Test parsing a topic with fewer than 5 parts."""
        topic = "$iothub/credentials/res"
        result = parse_request_id_from_topic(topic)
        assert result is None

    def test_empty_topic(self) -> None:
        """Test parsing an empty topic string."""
        topic = ""
        result = parse_request_id_from_topic(topic)
        assert result is None

    def test_topic_with_large_rid(self) -> None:
        """Test parsing a topic with a large request ID."""
        topic = "$iothub/credentials/res/200/?$rid=99999999"
        result = parse_request_id_from_topic(topic)
        assert result == "99999999"

    def test_topic_with_rid_value_one(self) -> None:
        """Test parsing a topic with request ID of 1."""
        topic = "$iothub/credentials/res/202/?$rid=1"
        result = parse_request_id_from_topic(topic)
        assert result == "1"

    def test_topic_with_multiple_query_params(self) -> None:
        """Test parsing a topic with many query parameters."""
        topic = "$iothub/credentials/res/200/?foo=bar&$rid=54321&$version=2&other=value"
        result = parse_request_id_from_topic(topic)
        assert result == "54321"


class TestConfigClassYamlFallback:
    """Tests for TestConfig YAML fallback functionality."""

    @pytest.fixture(autouse=True)
    def reset_yaml_config(self) -> None:
        """Reset the cached YAML config before each test."""
        TestConfig._yaml_config = None

    def test_env_var_takes_precedence_over_yaml(self, tmp_path: Path) -> None:
        """Test that environment variable takes precedence over YAML config."""
        config = TestConfig()
        yaml_content = "env:\n  - name: TEST_VAR\n    value: yaml_value\n"
        config_file = tmp_path / "testenv.yaml"
        config_file.write_text(yaml_content)

        with patch.dict(os.environ, {"TEST_VAR": "env_value"}):
            with patch.object(Path, "parent", tmp_path):
                result = config.get("TEST_VAR")

        assert result == "env_value"

    def test_yaml_fallback_when_env_not_set(self, tmp_path: Path) -> None:
        """Test that YAML config is used when env var is not set."""
        TestConfig._yaml_config = None
        config = TestConfig()
        yaml_content = "env:\n  - name: YAML_ONLY_VAR\n    value: yaml_value\n"

        # Write testenv.yaml to the locust_pkg directory
        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            config_path.write_text(yaml_content)
            TestConfig._yaml_config = None  # Reset cache

            # Ensure the env var is not set
            env_copy = os.environ.copy()
            if "YAML_ONLY_VAR" in env_copy:
                del env_copy["YAML_ONLY_VAR"]

            with patch.dict(os.environ, env_copy, clear=True):
                result = config.get("YAML_ONLY_VAR")

            assert result == "yaml_value"
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None

    def test_error_when_var_not_in_env_or_yaml(self) -> None:
        """Test that ValueError is raised when var is not in env or YAML."""
        TestConfig._yaml_config = None
        config = TestConfig()

        # Create an empty YAML config
        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            config_path.write_text("env: []\n")
            TestConfig._yaml_config = None

            env_copy = os.environ.copy()
            if "NONEXISTENT_VAR" in env_copy:
                del env_copy["NONEXISTENT_VAR"]

            with patch.dict(os.environ, env_copy, clear=True):
                with pytest.raises(ValueError, match="Required environment variable NONEXISTENT_VAR is not set"):
                    config.get("NONEXISTENT_VAR")
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None

    def test_yaml_config_caching(self) -> None:
        """Test that YAML config is loaded only once and cached."""
        TestConfig._yaml_config = None

        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            config_path.write_text("env:\n  - name: CACHE_TEST\n    value: cached\n")
            TestConfig._yaml_config = None

            # First load
            result1 = TestConfig._load_yaml_config()
            # Second load should return cached value
            result2 = TestConfig._load_yaml_config()

            assert result1 is result2
            assert result1.get("CACHE_TEST") == "cached"
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None

    def test_yaml_missing_file_returns_empty_dict(self) -> None:
        """Test that missing testenv.yaml returns empty dict."""
        TestConfig._yaml_config = None

        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()
            config_path.unlink()

        try:
            TestConfig._yaml_config = None
            result = TestConfig._load_yaml_config()
            assert result == {}
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            TestConfig._yaml_config = None

    def test_scale_config_path_used_when_set_and_exists(self, tmp_path: Path) -> None:
        """Test that SCALE_CONFIG_PATH is used when set and file exists."""
        TestConfig._yaml_config = None

        custom_config = tmp_path / "custom_config.yaml"
        custom_config.write_text("env:\n  - name: CUSTOM_VAR\n    value: custom_value\n")

        env_copy = os.environ.copy()
        env_copy["SCALE_CONFIG_PATH"] = str(custom_config)
        if "CUSTOM_VAR" in env_copy:
            del env_copy["CUSTOM_VAR"]

        try:
            with patch.dict(os.environ, env_copy, clear=True):
                TestConfig._yaml_config = None
                result = TestConfig._load_yaml_config()
                assert result.get("CUSTOM_VAR") == "custom_value"
        finally:
            TestConfig._yaml_config = None

    def test_scale_config_path_falls_back_when_file_not_exists(self) -> None:
        """Test that default path is used when SCALE_CONFIG_PATH file doesn't exist."""
        TestConfig._yaml_config = None

        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            config_path.write_text("env:\n  - name: DEFAULT_VAR\n    value: default_value\n")

            env_copy = os.environ.copy()
            env_copy["SCALE_CONFIG_PATH"] = "/nonexistent/path/config.yaml"
            if "DEFAULT_VAR" in env_copy:
                del env_copy["DEFAULT_VAR"]

            with patch.dict(os.environ, env_copy, clear=True):
                TestConfig._yaml_config = None
                result = TestConfig._load_yaml_config()
                assert result.get("DEFAULT_VAR") == "default_value"
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None

    def test_scale_config_path_not_set_uses_default(self) -> None:
        """Test that default path is used when SCALE_CONFIG_PATH is not set."""
        TestConfig._yaml_config = None

        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            config_path.write_text("env:\n  - name: FALLBACK_VAR\n    value: fallback_value\n")

            env_copy = {k: v for k, v in os.environ.items() if k not in ("SCALE_CONFIG_PATH", "FALLBACK_VAR")}

            with patch.dict(os.environ, env_copy, clear=True):
                TestConfig._yaml_config = None
                result = TestConfig._load_yaml_config()
                assert result.get("FALLBACK_VAR") == "fallback_value"
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None

    def test_get_optional_with_yaml_fallback(self) -> None:
        """Test that get_optional also falls back to YAML config."""
        TestConfig._yaml_config = None
        config = TestConfig()

        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            config_path.write_text("env:\n  - name: OPTIONAL_YAML_VAR\n    value: optional_value\n")
            TestConfig._yaml_config = None

            env_copy = os.environ.copy()
            if "OPTIONAL_YAML_VAR" in env_copy:
                del env_copy["OPTIONAL_YAML_VAR"]

            with patch.dict(os.environ, env_copy, clear=True):
                result = config.get_optional("OPTIONAL_YAML_VAR")

            assert result == "optional_value"
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None

    def test_get_optional_returns_none_when_not_found(self) -> None:
        """Test that get_optional returns None when var is not in env or YAML."""
        TestConfig._yaml_config = None
        config = TestConfig()

        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            config_path.write_text("env: []\n")
            TestConfig._yaml_config = None

            env_copy = os.environ.copy()
            if "MISSING_OPTIONAL_VAR" in env_copy:
                del env_copy["MISSING_OPTIONAL_VAR"]

            with patch.dict(os.environ, env_copy, clear=True):
                result = config.get_optional("MISSING_OPTIONAL_VAR")

            assert result is None
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None

    def test_yaml_value_converted_to_string(self) -> None:
        """Test that YAML values are converted to strings."""
        TestConfig._yaml_config = None
        config = TestConfig()

        import locust_pkg.utils as utils_module

        config_path = Path(utils_module.__file__).parent / "testenv.yaml"
        original_exists = config_path.exists()
        original_content = None
        if original_exists:
            original_content = config_path.read_text()

        try:
            # Use an integer value in YAML
            config_path.write_text("env:\n  - name: INT_VAR\n    value: 12345\n")
            TestConfig._yaml_config = None

            env_copy = os.environ.copy()
            if "INT_VAR" in env_copy:
                del env_copy["INT_VAR"]

            with patch.dict(os.environ, env_copy, clear=True):
                result = config.get("INT_VAR")

            assert result == "12345"
            assert isinstance(result, str)
        finally:
            if original_exists and original_content:
                config_path.write_text(original_content)
            elif config_path.exists():
                config_path.unlink()
            TestConfig._yaml_config = None


class TestConfigLogging:
    """Tests for TestConfig logging functionality."""

    @pytest.fixture(autouse=True)
    def reset_yaml_config(self) -> None:
        """Reset the cached YAML config before each test."""
        TestConfig._yaml_config = None

    def test_logs_value_on_first_access(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that the value is logged on first access when log_value=True."""
        import logging

        config = TestConfig()
        with patch.dict(os.environ, {"LOG_TEST_VAR": "test_value"}):
            with caplog.at_level(logging.INFO, logger="locust.test_config"):
                config.get("LOG_TEST_VAR", log_value=True)

        assert "Config LOG_TEST_VAR: test_value" in caplog.text

    def test_logs_set_when_log_value_false(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that 'set' is logged instead of value when log_value=False."""
        import logging

        config = TestConfig()
        with patch.dict(os.environ, {"SECRET_VAR": "secret_password"}):
            with caplog.at_level(logging.INFO, logger="locust.test_config"):
                config.get("SECRET_VAR", log_value=False)

        assert "Config SECRET_VAR: set" in caplog.text
        assert "secret_password" not in caplog.text

    def test_logs_unset_for_optional_missing_var(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that 'unset' is logged for missing optional variable."""
        import logging

        config = TestConfig()
        TestConfig._yaml_config = {}
        env_copy = {k: v for k, v in os.environ.items() if k != "MISSING_VAR"}
        with patch.dict(os.environ, env_copy, clear=True):
            with caplog.at_level(logging.INFO, logger="locust.test_config"):
                config.get_optional("MISSING_VAR")

        assert "Config MISSING_VAR: unset" in caplog.text

    def test_logs_only_once_per_key(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that each key is only logged once."""
        import logging

        config = TestConfig()
        with patch.dict(os.environ, {"REPEATED_VAR": "value"}):
            with caplog.at_level(logging.INFO, logger="locust.test_config"):
                config.get("REPEATED_VAR")
                caplog.clear()
                config.get("REPEATED_VAR")

        # Second access should not log
        assert "Config REPEATED_VAR" not in caplog.text

    def test_get_int_respects_log_value(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that get_int respects the log_value parameter."""
        import logging

        config = TestConfig()
        with patch.dict(os.environ, {"INT_VAR": "42"}):
            with caplog.at_level(logging.INFO, logger="locust.test_config"):
                config.get_int("INT_VAR", log_value=False)

        assert "Config INT_VAR: set" in caplog.text
        assert "42" not in caplog.text

    def test_get_bool_respects_log_value(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that get_bool respects the log_value parameter."""
        import logging

        config = TestConfig()
        with patch.dict(os.environ, {"BOOL_VAR": "true"}):
            with caplog.at_level(logging.INFO, logger="locust.test_config"):
                config.get_bool("BOOL_VAR", log_value=True)

        assert "Config BOOL_VAR: true" in caplog.text

    def test_get_optional_respects_log_value(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that get_optional respects the log_value parameter."""
        import logging

        config = TestConfig()
        with patch.dict(os.environ, {"OPT_VAR": "optional_value"}):
            with caplog.at_level(logging.INFO, logger="locust.test_config"):
                config.get_optional("OPT_VAR", log_value=False)

        assert "Config OPT_VAR: set" in caplog.text
        assert "optional_value" not in caplog.text
