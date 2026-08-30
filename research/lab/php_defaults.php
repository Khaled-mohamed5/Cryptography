<?php
/**
 * §6 - PHP is safe by default; LIBXML_NOENT is what makes it exploitable,
 * and LIBXML_NONET does not stop a local file read.
 *   php php_defaults.php     (run php_xxe_schemes.php first to create tmp/secret.txt)
 */
$dir = __DIR__ . '/tmp';
$xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"$dir/secret.txt\">]><r>&xxe;</r>";

function show(string $label, callable $fn): void
{
    libxml_use_internal_errors(true);
    libxml_clear_errors();
    try {
        $r = $fn();
    } catch (Throwable $t) {
        $r = 'EXC ' . $t->getMessage();
    }
    printf("%-46s => %s\n", $label, str_replace("\n", '\\n', trim((string) $r)) ?: '(blocked: empty)');
}

echo 'PHP ' . PHP_VERSION . ' | libxml ' . LIBXML_DOTTED_VERSION . "\n";
show('simplexml_load_string, DEFAULT flags', fn () => (string) @simplexml_load_string($xml));
show('simplexml_load_string, LIBXML_NOENT',  fn () => (string) @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT));
show('DOMDocument->loadXML, DEFAULT flags',  function () use ($xml) { $d = new DOMDocument(); @$d->loadXML($xml); return $d->documentElement->textContent; });
show('DOMDocument->loadXML, LIBXML_NOENT',   function () use ($xml) { $d = new DOMDocument(); @$d->loadXML($xml, LIBXML_NOENT); return $d->documentElement->textContent; });
show('DOMDocument, LIBXML_NOENT|LIBXML_NONET', function () use ($xml) { $d = new DOMDocument(); @$d->loadXML($xml, LIBXML_NOENT | LIBXML_NONET); return $d->documentElement->textContent; });
