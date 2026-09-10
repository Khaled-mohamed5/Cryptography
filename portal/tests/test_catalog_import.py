"""Unit tests for the supplier catalog parser."""

import pytest

from catalog_import import (
    MAX_DOCUMENT_BYTES,
    MAX_FIELD_CHARS,
    MAX_RECORDS,
    CatalogImportError,
    parse_catalog,
)

VALID = """<catalog>
  <product><name>Sample Product</name><sku>SKU-1</sku><note>imported</note></product>
</catalog>"""


def test_parses_a_valid_catalog():
    parsed = parse_catalog(VALID)
    assert parsed["problems"] == []
    assert parsed["records"] == [
        {
            "name": "Sample Product",
            "sku": "SKU-1",
            "note": "imported",
            "position": 1,
        }
    ]


def test_accepts_bytes_as_well_as_text():
    assert parse_catalog(VALID.encode()) == parse_catalog(VALID)


def test_missing_optional_field_is_empty_not_an_error():
    parsed = parse_catalog("<catalog><product><name>N</name><sku>S</sku></product></catalog>")
    assert parsed["records"][0]["note"] == ""
    assert parsed["problems"] == []


def test_field_text_is_whitespace_collapsed():
    parsed = parse_catalog(
        "<catalog><product><name>  Two \n  words </name><sku>S</sku></product></catalog>"
    )
    assert parsed["records"][0]["name"] == "Two words"


def test_unknown_child_elements_are_ignored():
    parsed = parse_catalog(
        "<catalog><product><name>N</name><sku>S</sku><price>9</price></product></catalog>"
    )
    assert set(parsed["records"][0]) == {"name", "sku", "note", "position"}


# --- documents rejected outright -------------------------------------------


@pytest.mark.parametrize(
    "label, document",
    [
        (
            "entity reading a local file",
            '<?xml version="1.0"?>'
            '<!DOCTYPE catalog [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<catalog><product><name>&xxe;</name><sku>S</sku></product></catalog>",
        ),
        (
            "entity reaching a network address",
            '<!DOCTYPE catalog [<!ENTITY x SYSTEM "http://169.254.169.254/">]>'
            "<catalog><product><name>&x;</name><sku>S</sku></product></catalog>",
        ),
        (
            "parameter entity",
            '<!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd">%p;]><catalog/>',
        ),
        (
            "external DTD reference",
            '<!DOCTYPE catalog SYSTEM "http://supplier.example/catalog.dtd">'
            "<catalog><product><name>N</name><sku>S</sku></product></catalog>",
        ),
        (
            "entity expansion",
            '<!DOCTYPE l [<!ENTITY a "aa"><!ENTITY b "&a;&a;"><!ENTITY c "&b;&b;">]>'
            "<catalog><product><name>&c;</name><sku>S</sku></product></catalog>",
        ),
        (
            "bare doctype",
            "<!DOCTYPE catalog>"
            "<catalog><product><name>N</name><sku>S</sku></product></catalog>",
        ),
    ],
)
def test_doctype_and_entity_constructs_are_refused(label, document):
    with pytest.raises(CatalogImportError) as raised:
        parse_catalog(document)
    assert "not accepted" in raised.value.message, label


def test_rejection_never_leaks_local_file_contents():
    document = (
        '<!DOCTYPE catalog [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<catalog><product><name>&xxe;</name><sku>S</sku></product></catalog>"
    )
    with pytest.raises(CatalogImportError) as raised:
        parse_catalog(document)
    reported = f"{raised.value.message} {raised.value.detail or ''}"
    assert "root:" not in reported
    assert "/bin/" not in reported


def test_malformed_xml_is_rejected():
    with pytest.raises(CatalogImportError, match="not well-formed"):
        parse_catalog("<catalog><product><name>N</name></catalog>")


def test_empty_document_is_rejected():
    with pytest.raises(CatalogImportError, match="empty"):
        parse_catalog("   \n  ")


def test_wrong_root_element_is_rejected():
    with pytest.raises(CatalogImportError, match="root element"):
        parse_catalog("<invoices><product><name>N</name><sku>S</sku></product></invoices>")


def test_catalog_without_products_is_rejected():
    with pytest.raises(CatalogImportError, match="no <product> records"):
        parse_catalog("<catalog></catalog>")


def test_oversized_document_is_rejected_before_parsing():
    document = b"<catalog>" + b"<product/>" * 200_000 + b"</catalog>"
    assert len(document) > MAX_DOCUMENT_BYTES
    with pytest.raises(CatalogImportError, match="import limit"):
        parse_catalog(document)


def test_too_many_records_are_rejected():
    record = "<product><name>N</name><sku>S</sku></product>"
    document = f"<catalog>{record * (MAX_RECORDS + 1)}</catalog>"
    with pytest.raises(CatalogImportError, match="import limit"):
        parse_catalog(document)


def test_record_count_at_the_limit_is_accepted():
    records = "".join(
        f"<product><name>N</name><sku>S-{i}</sku></product>"
        for i in range(MAX_RECORDS)
    )
    parsed = parse_catalog(f"<catalog>{records}</catalog>")
    assert len(parsed["records"]) == MAX_RECORDS


# --- records skipped individually ------------------------------------------


def test_record_missing_required_fields_is_skipped():
    parsed = parse_catalog(
        "<catalog>"
        "<product><name>Keeper</name><sku>SKU-1</sku></product>"
        "<product><name>No sku</name></product>"
        "<product><sku>SKU-3</sku></product>"
        "</catalog>"
    )
    assert [r["sku"] for r in parsed["records"]] == ["SKU-1"]
    assert [p["reason"] for p in parsed["problems"]] == [
        "missing <sku>",
        "missing <name>",
    ]


def test_repeated_sku_is_skipped_case_insensitively():
    parsed = parse_catalog(
        "<catalog>"
        "<product><name>First</name><sku>SKU-1</sku></product>"
        "<product><name>Again</name><sku>sku-1</sku></product>"
        "</catalog>"
    )
    assert len(parsed["records"]) == 1
    assert parsed["problems"][0]["reason"] == "SKU repeats record 1"


def test_overlong_field_is_skipped():
    long_note = "x" * (MAX_FIELD_CHARS + 1)
    parsed = parse_catalog(
        f"<catalog><product><name>N</name><sku>S</sku>"
        f"<note>{long_note}</note></product></catalog>"
    )
    assert parsed["records"] == []
    assert "longer than" in parsed["problems"][0]["reason"]


def test_problem_report_truncates_the_offending_sku():
    parsed = parse_catalog(
        f"<catalog><product><sku>{'S' * 300}</sku></product></catalog>"
    )
    assert len(parsed["problems"][0]["sku"]) == 64


def test_unknown_encoding_declaration_is_rejected_not_crashed():
    with pytest.raises(CatalogImportError, match="could not be decoded"):
        parse_catalog(b'<?xml version="1.0" encoding="bogus-9"?><catalog/>')


def test_malformed_encoding_declaration_is_rejected_not_crashed():
    with pytest.raises(CatalogImportError):
        parse_catalog(b'<?xml version="1.0" encoding="\xff\xfe"?><catalog/>')


def test_binary_junk_is_rejected():
    with pytest.raises(CatalogImportError):
        parse_catalog(b"\x00\x01\x02")


def test_nested_markup_in_a_field_is_not_folded_into_its_text():
    parsed = parse_catalog(
        "<catalog><product><name>Hi <b>there</b></name><sku>S</sku></product></catalog>"
    )
    assert parsed["records"][0]["name"] == "Hi"
