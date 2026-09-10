"""Parsing of supplier catalog documents for the Data Import portal.

Supplier feeds arrive as XML from outside the organisation, so the document is
treated as hostile input throughout. Parsing goes through ``defusedxml`` with
document type declarations, entity declarations and external references all
refused, which closes off XML external entity (XXE) file disclosure and SSRF as
well as entity-expansion denial of service such as "billion laughs". The caps
below bound the work a single document can ask for.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError

from defusedxml.ElementTree import fromstring as _defused_fromstring
from defusedxml.common import (
    DefusedXmlException,
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)

#: Largest supplier document accepted, in bytes.
MAX_DOCUMENT_BYTES = 1 << 20  # 1 MiB

#: Largest number of ``<product>`` records accepted in one document.
MAX_RECORDS = 500

#: Longest value accepted for a single field, in characters.
MAX_FIELD_CHARS = 512

#: Fields read from each ``<product>``; anything else in the record is ignored.
FIELDS = ("name", "sku", "note")

#: Fields that must be present and non-empty for a record to be imported.
REQUIRED_FIELDS = ("name", "sku")

ROOT_TAG = "catalog"
RECORD_TAG = "product"


class CatalogImportError(Exception):
    """Raised when a supplier document cannot be accepted at all.

    ``message`` is safe to show to the operator who submitted the document.
    ``detail`` carries the parser's own wording where that helps them fix the
    feed; it never contains anything drawn from the server's environment.
    """

    def __init__(self, message: str, detail: str | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


def parse_catalog(document: bytes | str) -> dict:
    """Parse a supplier catalog document into previewable records.

    Returns a dict with ``records`` (the records that validated) and
    ``problems`` (per-record complaints about the ones that did not). A document
    that cannot be parsed or is structurally wrong raises
    :class:`CatalogImportError` instead -- that is a rejection of the whole
    document rather than of individual records.
    """
    raw = document.encode("utf-8") if isinstance(document, str) else bytes(document)

    if not raw.strip():
        raise CatalogImportError("The document is empty.")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise CatalogImportError(
            f"The document is {len(raw):,} bytes; the import limit is "
            f"{MAX_DOCUMENT_BYTES:,} bytes."
        )

    root = _parse_hardened(raw)

    if root.tag != ROOT_TAG:
        raise CatalogImportError(
            f"Expected a <{ROOT_TAG}> root element, found <{root.tag}>."
        )

    products = root.findall(RECORD_TAG)
    if not products:
        raise CatalogImportError(
            f"The catalog contains no <{RECORD_TAG}> records."
        )
    if len(products) > MAX_RECORDS:
        raise CatalogImportError(
            f"The catalog contains {len(products):,} records; the import limit "
            f"is {MAX_RECORDS:,}."
        )

    records: list[dict] = []
    problems: list[dict] = []
    skus_seen: dict[str, int] = {}

    for position, product in enumerate(products, start=1):
        record, complaint = _read_record(product, position, skus_seen)
        if complaint is not None:
            problems.append(complaint)
            continue
        skus_seen[record["sku"].casefold()] = position
        records.append(record)

    return {"records": records, "problems": problems}


def _parse_hardened(raw: bytes) -> Element:
    """Parse ``raw`` with DTDs, entities and external references all refused."""
    try:
        return _defused_fromstring(
            raw,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DTDForbidden:
        raise CatalogImportError(
            "Document type declarations (<!DOCTYPE ...>) are not accepted."
        ) from None
    except EntitiesForbidden:
        raise CatalogImportError("Entity declarations are not accepted.") from None
    except ExternalReferenceForbidden:
        raise CatalogImportError(
            "References to external documents are not accepted."
        ) from None
    except DefusedXmlException:
        raise CatalogImportError(
            "The document uses XML features that are not accepted."
        ) from None
    except ParseError as exc:
        raise CatalogImportError(
            "The document is not well-formed XML.", detail=str(exc)
        ) from None
    except (ValueError, LookupError) as exc:
        # An encoding declaration that is malformed (ValueError) or names a
        # codec that does not exist (LookupError) surfaces here rather than as
        # a ParseError.
        raise CatalogImportError(
            "The document could not be decoded.", detail=str(exc)
        ) from None


def _read_record(
    product: Element, position: int, skus_seen: dict[str, int]
) -> tuple[dict, None] | tuple[None, dict]:
    """Read one ``<product>``, returning either the record or a complaint."""
    record = {field: _read_field(product, field) for field in FIELDS}

    missing = [field for field in REQUIRED_FIELDS if not record[field]]
    if missing:
        return None, _complaint(
            position,
            record,
            "missing " + " and ".join(f"<{field}>" for field in missing),
        )

    overlong = [
        field for field in FIELDS if len(record[field]) > MAX_FIELD_CHARS
    ]
    if overlong:
        return None, _complaint(
            position,
            record,
            f"{overlong[0]} is longer than {MAX_FIELD_CHARS} characters",
        )

    duplicate_of = skus_seen.get(record["sku"].casefold())
    if duplicate_of is not None:
        return None, _complaint(
            position,
            record,
            f"SKU repeats record {duplicate_of}",
        )

    record["position"] = position
    return record, None


def _read_field(product: Element, field: str) -> str:
    """Return the collapsed text of ``<field>`` within ``product``."""
    element = product.find(field)
    if element is None or element.text is None:
        return ""
    return " ".join(element.text.split())


def _complaint(position: int, record: dict, reason: str) -> dict:
    """Describe why one record was left out, without echoing its full text."""
    sku = record.get("sku") or ""
    return {
        "position": position,
        "sku": sku[:64],
        "reason": reason,
    }
