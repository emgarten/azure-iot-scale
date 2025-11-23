from datetime import datetime, timezone

import orjson


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
