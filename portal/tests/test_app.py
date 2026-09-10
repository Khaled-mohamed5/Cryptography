"""Tests for the Data Import page and its endpoint."""

from catalog_import import MAX_DOCUMENT_BYTES
from conftest import post_xml

VALID = (
    "<catalog><product><name>Sample Product</name><sku>SKU-1</sku>"
    "<note>imported</note></product></catalog>"
)


# --- the page ---------------------------------------------------------------


def test_import_page_renders(client):
    page = client.get("/catalog/import")
    body = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "<h1>Data Import</h1>" in body
    assert 'action="/api/catalog/import"' not in body  # posted by fetch, not a form


def test_import_page_marks_its_own_nav_entry_active(client):
    body = client.get("/catalog/import").get_data(as_text=True)
    assert '<a href="/catalog/import" class="active">' in body
    assert '<a href="/products" class="">' in body


def test_page_never_renders_a_missing_user_as_none(client):
    body = client.get("/catalog/import").get_data(as_text=True)
    assert "None None" not in body


def test_root_redirects_to_the_import_page(client):
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/catalog/import")


def test_sidebar_links_all_resolve(client):
    body = client.get("/catalog/import").get_data(as_text=True)
    for path in (
        "/dashboard",
        "/products",
        "/directory",
        "/notes",
        "/reports/preview",
        "/profile",
        "/help",
    ):
        assert f'href="{path}"' in body
        assert client.get(path).status_code == 200


def test_static_assets_are_served(client):
    assert client.get("/static/css/style.css").status_code == 200
    assert client.get("/static/favicon.svg").status_code == 200


# --- the endpoint -----------------------------------------------------------


def test_valid_document_is_imported(client):
    response = post_xml(client, VALID)
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["status"] == "ok"
    assert payload["imported"] == 1
    assert payload["skipped"] == 0
    assert payload["records"][0]["sku"] == "SKU-1"
    assert "no records were written" in payload["note"].lower()


def test_partial_import_reports_skipped_records(client):
    response = post_xml(
        client,
        "<catalog>"
        "<product><name>Keeper</name><sku>SKU-1</sku></product>"
        "<product><name>No sku</name></product>"
        "</catalog>",
    )
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["status"] == "partial"
    assert payload["imported"] == 1
    assert payload["skipped"] == 1
    assert payload["problems"][0]["position"] == 2


def test_xxe_attempt_is_refused_with_400(client):
    response = post_xml(
        client,
        '<!DOCTYPE catalog [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<catalog><product><name>&xxe;</name><sku>S</sku></product></catalog>",
    )
    payload = response.get_json()
    assert response.status_code == 400
    assert payload["status"] == "rejected"
    assert "not accepted" in payload["error"]
    assert "root:" not in response.get_data(as_text=True)


def test_entity_expansion_attempt_is_refused_with_400(client):
    response = post_xml(
        client,
        '<!DOCTYPE l [<!ENTITY a "aa"><!ENTITY b "&a;&a;">]>'
        "<catalog><product><name>&b;</name><sku>S</sku></product></catalog>",
    )
    assert response.status_code == 400
    assert response.get_json()["status"] == "rejected"


def test_malformed_document_is_refused_with_400(client):
    response = post_xml(client, "<catalog><product></catalog>")
    payload = response.get_json()
    assert response.status_code == 400
    assert "not well-formed" in payload["error"]
    assert payload["detail"]


def test_empty_body_is_refused_with_400(client):
    assert post_xml(client, "").status_code == 400


def test_non_xml_content_type_is_refused_with_415(client):
    response = post_xml(client, "{}", content_type="application/json")
    assert response.status_code == 415
    assert "XML content type" in response.get_json()["error"]


def test_xml_content_type_variants_are_accepted(client):
    for content_type in (
        "text/xml",
        "application/xml; charset=utf-8",
        "application/vnd.supplier+xml",
    ):
        assert post_xml(client, VALID, content_type=content_type).status_code == 200


def test_oversized_body_is_refused_with_413(client):
    document = b"<catalog>" + b"<product/>" * 200_000 + b"</catalog>"
    assert len(document) > MAX_DOCUMENT_BYTES
    response = post_xml(client, document)
    assert response.status_code == 413
    assert response.get_json()["status"] == "rejected"


def test_endpoint_rejects_get(client):
    response = client.get("/api/catalog/import")
    assert response.status_code == 405
    assert response.get_json()["status"] == "rejected"


def test_unknown_api_path_returns_json_not_html(client):
    response = client.get("/api/nope")
    assert response.status_code == 404
    assert response.get_json()["status"] == "rejected"


def test_error_responses_carry_no_traceback(client):
    body = post_xml(client, "<catalog><oops></catalog>").get_data(as_text=True)
    assert "Traceback" not in body
    assert "File \"" not in body


# --- rendering of supplier-controlled text ----------------------------------


def test_supplier_text_is_returned_as_json_data_not_markup(client):
    response = post_xml(
        client,
        "<catalog><product><name>&lt;img src=x onerror=alert(1)&gt;</name>"
        "<sku>SKU-1</sku></product></catalog>",
    )
    payload = response.get_json()
    # The markup round-trips as a JSON string value. It is inert because the
    # response is typed as JSON and cannot be content-sniffed into HTML, and
    # the page writes it through textContent rather than innerHTML.
    assert payload["records"][0]["name"] == "<img src=x onerror=alert(1)>"
    assert response.mimetype == "application/json"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_security_headers_are_set_on_every_response(client):
    for path in ("/catalog/import", "/api/catalog/import"):
        response = (
            client.get(path) if path == "/catalog/import" else post_xml(client, VALID)
        )
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_page_carries_no_inline_script_or_style(client):
    # The content security policy has no 'unsafe-inline', so inline script or
    # style attributes in the page would silently stop working.
    body = client.get("/catalog/import").get_data(as_text=True)
    assert "style=" not in body
    assert "onclick=" not in body
    assert "<script>" not in body
    assert '<script src="/static/js/import.js">' in body


def test_search_query_is_escaped_on_the_page(client):
    body = client.get("/search?q=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_unknown_encoding_declaration_returns_400_not_500(client):
    response = post_xml(client, b'<?xml version="1.0" encoding="bogus-9"?><catalog/>')
    assert response.status_code == 400
    assert response.get_json()["status"] == "rejected"
    assert "Traceback" not in response.get_data(as_text=True)


def test_missing_content_type_is_accepted(client):
    response = client.post("/api/catalog/import", data=VALID)
    assert response.status_code == 200
