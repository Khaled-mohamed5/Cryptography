"""Meridian Operations Portal -- Data Import.

Serves the Catalog > Data Import screen and the endpoint behind it,
``POST /api/catalog/import``, which parses a supplier XML feed and returns the
parsed records for preview. Importing is a preview step: nothing is written to
the catalog here.
"""

from __future__ import annotations

from flask import Flask, jsonify, redirect, render_template, request, url_for

from catalog_import import (
    MAX_DOCUMENT_BYTES,
    MAX_FIELD_CHARS,
    MAX_RECORDS,
    CatalogImportError,
    parse_catalog,
)

XML_CONTENT_TYPES = ("application/xml", "text/xml")

SAMPLE_DOCUMENT = """<catalog>
  <product>
    <name>Sample Product</name>
    <sku>SKU-1</sku>
    <note>imported</note>
  </product>
</catalog>"""

# The sidebar. Only Data Import is built out; the rest render a placeholder so
# the shell navigates coherently without implying features that do not exist.
NAV = [
    {
        "caption": "Overview",
        "links": [{"href": "/dashboard", "label": "Dashboard", "icon": "i-dash"}],
    },
    {
        "caption": "Catalog",
        "links": [
            {"href": "/products", "label": "Products", "icon": "i-box"},
            {"href": "/catalog/import", "label": "Data Import", "icon": "i-up"},
        ],
    },
    {
        "caption": "Directory",
        "links": [
            {"href": "/directory", "label": "Staff Directory", "icon": "i-users"}
        ],
    },
    {
        "caption": "Workspace",
        "links": [
            {"href": "/notes", "label": "Notes", "icon": "i-note"},
            {
                "href": "/reports/preview",
                "label": "Notification Templates",
                "icon": "i-tpl",
            },
        ],
    },
    {
        "caption": "Account",
        "links": [
            {"href": "/profile", "label": "My Account", "icon": "i-user"},
            {"href": "/help", "label": "Help Center", "icon": "i-help"},
        ],
    },
]

PLACEHOLDER_PAGES = {
    "/dashboard": ("Overview", "Dashboard"),
    "/products": ("Catalog", "Products"),
    "/directory": ("Directory", "Staff Directory"),
    "/notes": ("Workspace", "Notes"),
    "/reports/preview": ("Workspace", "Notification Templates"),
    "/profile": ("Account", "My Account"),
    "/help": ("Account", "Help Center"),
}


def create_app() -> Flask:
    app = Flask(__name__)
    # Refuse an oversized body before it is read into memory. The parser applies
    # the same limit itself, for callers that do not come through Flask.
    app.config["MAX_CONTENT_LENGTH"] = MAX_DOCUMENT_BYTES

    @app.context_processor
    def shell_context() -> dict:
        return {
            "nav": NAV,
            "active_path": request.path,
            "user": {"name": "Operations User", "role": "User"},
        }

    @app.after_request
    def security_headers(response):
        # The endpoint returns supplier-controlled text inside a JSON body, so
        # stop a browser content-sniffing it into something executable, and keep
        # the page out of frames and off third-party origins.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'",
        )
        return response

    @app.get("/")
    def index():
        return redirect(url_for("catalog_import_page"))

    @app.get("/catalog/import")
    def catalog_import_page():
        return render_template(
            "catalog_import.html",
            sample=SAMPLE_DOCUMENT,
            max_bytes=MAX_DOCUMENT_BYTES,
            max_records=MAX_RECORDS,
            max_field=MAX_FIELD_CHARS,
        )

    @app.post("/api/catalog/import")
    def catalog_import_api():
        content_type = (request.mimetype or "").lower()
        if content_type and not (
            content_type in XML_CONTENT_TYPES or content_type.endswith("+xml")
        ):
            return (
                jsonify(
                    status="rejected",
                    error=(
                        "Expected an XML content type, received "
                        f"'{content_type[:64]}'."
                    ),
                ),
                415,
            )

        document = request.get_data(cache=False)
        try:
            parsed = parse_catalog(document)
        except CatalogImportError as exc:
            payload = {"status": "rejected", "error": exc.message}
            if exc.detail:
                payload["detail"] = exc.detail
            return jsonify(payload), 400

        records, problems = parsed["records"], parsed["problems"]
        return jsonify(
            status="ok" if not problems else "partial",
            note="Preview only -- no records were written to the catalog.",
            received_bytes=len(document),
            imported=len(records),
            skipped=len(problems),
            records=records,
            problems=problems,
        )

    @app.get("/search")
    def search():
        return render_template(
            "placeholder.html",
            crumbs="Catalog",
            heading="Search",
            query=request.args.get("q", ""),
        )

    @app.get("/logout")
    def logout():
        return redirect(url_for("catalog_import_page"))

    for path, (crumbs, heading) in PLACEHOLDER_PAGES.items():
        _register_placeholder(app, path, crumbs, heading)

    @app.errorhandler(413)
    def payload_too_large(_error):
        message = (
            f"The document exceeds the {MAX_DOCUMENT_BYTES:,} byte import limit."
        )
        if request.path.startswith("/api/"):
            return jsonify(status="rejected", error=message), 413
        return message, 413

    @app.errorhandler(500)
    def internal_error(_error):
        # Flask logs the exception; the response says nothing about it. A
        # supplier document must never be able to draw a traceback out of the
        # endpoint.
        if request.path.startswith("/api/"):
            return (
                jsonify(status="error", error="The document could not be processed."),
                500,
            )
        return "Internal server error", 500

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify(status="rejected", error="No such endpoint."), 404
        return render_template("placeholder.html", crumbs="", heading="Not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        if request.path.startswith("/api/"):
            return (
                jsonify(status="rejected", error="This endpoint accepts POST only."),
                405,
            )
        return "Method not allowed", 405

    return app


def _register_placeholder(app: Flask, path: str, crumbs: str, heading: str) -> None:
    """Route ``path`` to the generic 'not part of this build' page."""

    def view():
        return render_template("placeholder.html", crumbs=crumbs, heading=heading)

    app.add_url_rule(path, endpoint=f"placeholder{path}", view_func=view)


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
