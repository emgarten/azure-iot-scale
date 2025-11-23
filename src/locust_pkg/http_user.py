import logging
from locust import HttpUser, task, constant_pacing

logger = logging.getLogger("locust.http_user")


class BasicHttpUser(HttpUser):
    """Basic HTTP user that makes calls to the host every 5 seconds."""

    wait_time = constant_pacing(5)  # type: ignore[no-untyped-call]  # Wait 5 seconds between tasks

    @task
    def get_request(self) -> None:
        """Make a GET request to the host."""
        try:
            # Make a GET request to the root path
            # The host is configured in Locust command line (--host parameter)
            with self.client.get("/", catch_response=True) as response:
                if response.status_code == 200:
                    logger.debug("GET request successful")
                else:
                    logger.warning(f"GET request returned status code: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to make GET request: {str(e)}")
