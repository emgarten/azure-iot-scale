"""Basic Locust user for load testing HTTP requests to Bing."""

from locust import HttpUser, task, between


class TestUser(HttpUser):
    """Locust user that makes HTTP requests to Bing."""

    # Wait between 1 and 3 seconds between tasks
    wait_time = between(1, 3)  # type: ignore[no-untyped-call]

    # Set the host to Bing
    host = "https://www.bing.com"

    @task
    def get_homepage(self) -> None:
        """Make a GET request to the Bing homepage."""
        self.client.get("/")
