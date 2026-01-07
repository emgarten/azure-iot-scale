"""Tests for utils.py module."""

from datetime import datetime, timezone

import orjson

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
        assert result == 66641568

    def test_valid_topic_with_rid_and_version(self) -> None:
        """Test parsing a topic with $rid and other parameters."""
        topic = "$iothub/credentials/res/200/?$rid=12345&$version=1"
        result = parse_request_id_from_topic(topic)
        assert result == 12345

    def test_topic_with_rid_not_first_param(self) -> None:
        """Test parsing when $rid is not the first query parameter."""
        topic = "$iothub/credentials/res/200/?$version=1&$rid=99999"
        result = parse_request_id_from_topic(topic)
        assert result == 99999

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

    def test_topic_with_invalid_rid_value(self) -> None:
        """Test parsing a topic with non-integer $rid value."""
        topic = "$iothub/credentials/res/202/?$rid=invalid"
        result = parse_request_id_from_topic(topic)
        assert result is None

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
        assert result == 99999999

    def test_topic_with_rid_value_one(self) -> None:
        """Test parsing a topic with request ID of 1."""
        topic = "$iothub/credentials/res/202/?$rid=1"
        result = parse_request_id_from_topic(topic)
        assert result == 1

    def test_topic_with_multiple_query_params(self) -> None:
        """Test parsing a topic with many query parameters."""
        topic = "$iothub/credentials/res/200/?foo=bar&$rid=54321&$version=2&other=value"
        result = parse_request_id_from_topic(topic)
        assert result == 54321
