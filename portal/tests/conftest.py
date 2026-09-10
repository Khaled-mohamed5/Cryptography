import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def post_xml(client, document, content_type="application/xml"):
    return client.post(
        "/api/catalog/import", data=document, content_type=content_type
    )
