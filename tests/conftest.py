# tests/conftest.py
import io
import pytest

@pytest.fixture
def make_environ():
    def _make(
        path: str = "/",
        method: str = "GET",
        query: str = "",
        body: bytes = b"",
        headers: dict | None = None,
    ) -> dict:
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        if headers:
            env.update(headers)
        return env
    return _make