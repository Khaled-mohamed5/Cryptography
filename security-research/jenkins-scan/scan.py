#!/usr/bin/env python3
"""Triage scanner for Jenkins plugin sources.

Finds Stapler web methods (do*) that reach interesting sinks without a
permission check or POST requirement -- the shape behind most Jenkins security
advisories -- plus XXE-prone parser construction and plaintext secret fields.

Accuracy notes (learned from false positives on support-core-plugin):
  * a class implementing StaplerProxy whose getTarget() checks a permission
    gates its whole URL space, so its do* methods are NOT unguarded;
  * `do*` is not always a web method -- doRun() on PeriodicWork and the
    servlet doGet/doPost overrides are internal APIs;
  * @Restricted(NoExternalUse.class) is NOT a security control: such methods
    are still reachable over HTTP, and advisories are filed against them;
  * comments must be blanked in place, not deleted, or reported line numbers
    drift away from the real source.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WEB_METHOD = re.compile(
    r"(?:public|protected)\s+(?:static\s+|final\s+|synchronized\s+)*"
    r"[\w<>\[\],\s.?@]+?\s+(do[A-Z]\w*)\s*\(",
)

# do* methods that Stapler never routes to.
NOT_WEB_METHODS = {"doRun", "doGet", "doPost", "doPut", "doDelete_", "doFilter", "doClose", "doExecute"}

PERMISSION_MARKERS = (
    "checkPermission",
    "hasPermission",
    "checkAnyPermission",
    "hasAnyPermission",
    "checkAdmin",
    "verifyAdmin",
    "checkAccess",
    "requirePOST",
    "Jenkins.ADMINISTER",
    "Item.CONFIGURE",
    "Item.EXTENDED_READ",
    "Computer.CONFIGURE",
)
POST_MARKERS = ("@RequirePOST", "@POST")

SINKS = {
    "credentials": (
        "lookupCredentials", "CredentialsProvider", "CredentialsMatchers",
        "StandardUsernamePassword", "getPassword", "getApiToken", "Secret.",
    ),
    "outbound": (
        "new URL(", "openConnection", "HttpClient", "HttpGet", "HttpPost",
        "URLConnection", "Socket(",
    ),
    "filesystem": (
        "new File(", "new FilePath(", "Files.copy", "Files.read", "Files.new",
        "Files.list", "Files.walk", "FileUtils", "FileInputStream", "getRootDir",
    ),
    "process": ("Runtime.getRuntime", "ProcessBuilder", "launcher.launch"),
    "xml": ("DocumentBuilder", "SAXParser", "XMLInputFactory", "SAXReader",
            "TransformerFactory", "unmarshal"),
    "item-lookup": ("getItemByFullName", "getAllItems", "getJob("),
    "writes": (".save()", ".delete()", "setDescription", "deleteDirectory"),
    "response": ("rsp.getOutputStream", "serveFile", "sendRedirect", "getWriter",
                 "HttpResponses", "setContentType"),
}

XXE_FACTORIES = (
    "DocumentBuilderFactory.newInstance", "SAXParserFactory.newInstance",
    "XMLInputFactory.newInstance", "TransformerFactory.newInstance",
    "new SAXReader(", "XPathFactory.newInstance",
)
XXE_GUARDS = (
    "disallow-doctype-decl", "FEATURE_SECURE_PROCESSING",
    "external-general-entities", "external-parameter-entities",
    "setXIncludeAware(false)", "setExpandEntityReferences(false)",
    "ACCESS_EXTERNAL_DTD", "SecureXmlParserFactory", "XMLUtils",
)

SECRET_FIELD = re.compile(
    r"(?:private|protected|public)\s+(?:final\s+)?String\s+"
    r"(\w*(?:[Pp]assword|[Ss]ecret|[Tt]oken|[Aa]piKey|[Pp]assphrase)\w*)\s*[;=]"
)


def blank_noise(source: str) -> str:
    """Blank comments and string literals in place, preserving every offset."""
    out = list(source)
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char == "/" and index + 1 < length and source[index + 1] == "/":
            while index < length and source[index] != "\n":
                out[index] = " "
                index += 1
        elif char == "/" and index + 1 < length and source[index + 1] == "*":
            while index < length and not (source[index] == "/" and source[index - 1] == "*" and index > 0):
                if source[index] != "\n":
                    out[index] = " "
                index += 1
            if index < length:
                out[index] = " "
                index += 1
        elif char in "\"'":
            quote = char
            index += 1
            while index < length and source[index] != quote:
                if source[index] == "\\":
                    out[index] = " "
                    index += 1
                if index < length and source[index] != "\n":
                    out[index] = " "
                index += 1
            index += 1
        else:
            index += 1
    return "".join(out)


def class_spans(source: str) -> list[tuple[str, int, int, str]]:
    """Return (name, body_start, body_end, declaration) for every class."""
    spans = []
    for match in re.finditer(r"\b(?:class|interface|enum)\s+(\w+)([^{;]*)\{", source):
        start = match.end() - 1
        depth = 0
        end = len(source)
        for index in range(start, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        spans.append((match.group(1), start, end, match.group(0)))
    return spans


def innermost_class(spans, position):
    best = None
    for name, start, end, declaration in spans:
        if start <= position <= end and (best is None or start > best[1]):
            best = (name, start, end, declaration)
    return best


def method_body(source: str, from_index: int) -> str:
    brace = source.find("{", from_index)
    semicolon = source.find(";", from_index)
    if brace == -1 or (semicolon != -1 and semicolon < brace):
        return ""  # abstract / interface declaration
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    return source[brace:]


def proxy_guarded(source: str, span) -> bool:
    """True when the enclosing class gates its whole URL space via StaplerProxy."""
    if span is None:
        return False
    name, start, end, declaration = span
    if "StaplerProxy" not in declaration:
        return False
    body = source[start:end]
    match = re.search(r"\bgetTarget\s*\(\s*\)", body)
    if not match:
        return False
    target_body = method_body(body, match.end())
    return any(marker in target_body for marker in PERMISSION_MARKERS)


def scan_file(path: Path, root: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    source = blank_noise(raw)
    spans = class_spans(source)
    relative = str(path.relative_to(root))
    findings: list[dict] = []

    def line_of(offset: int) -> int:
        return raw[:offset].count("\n") + 1

    for match in WEB_METHOD.finditer(source):
        name = match.group(1)
        if name in NOT_WEB_METHODS:
            continue
        body = method_body(source, match.end())
        if not body:
            continue
        span = innermost_class(spans, match.start())
        head = source[max(0, match.start() - 300) : match.start()]
        context = head + body
        if any(marker in context for marker in PERMISSION_MARKERS):
            continue
        if proxy_guarded(source, span):
            continue
        hit = sorted(
            {
                label
                for label, needles in SINKS.items()
                if any(needle in body for needle in needles)
            }
        )
        if not hit:
            continue
        posted = any(marker in head for marker in POST_MARKERS)
        ancestor = "@AncestorInPath" in source[match.start() : match.start() + len(body)]
        score = (
            len(hit)
            + (0 if posted else 1)
            + (3 if "credentials" in hit else 0)
            + (3 if "outbound" in hit else 0)
            + (2 if "response" in hit and "filesystem" in hit else 0)
            + (1 if ancestor else 0)
        )
        findings.append(
            {
                "kind": "unguarded-endpoint",
                "file": relative,
                "line": line_of(match.start()),
                "detail": f"{span[0] if span else '?'}.{name}()",
                "sinks": hit,
                "post": posted,
                "score": score,
            }
        )

    for factory in XXE_FACTORIES:
        for match in re.finditer(re.escape(factory), source):
            window = source[match.start() : match.start() + 1500]
            if any(guard in window for guard in XXE_GUARDS):
                continue
            findings.append({
                "kind": "xxe-candidate", "file": relative, "line": line_of(match.start()),
                "detail": factory, "sinks": ["xml"], "post": False, "score": 4,
            })

    for match in SECRET_FIELD.finditer(source):
        if "Secret" in source[max(0, match.start() - 200) : match.start()]:
            continue
        if "@DataBoundConstructor" not in source and "@DataBoundSetter" not in source:
            continue
        findings.append({
            "kind": "plaintext-secret-field", "file": relative, "line": line_of(match.start()),
            "detail": f"String {match.group(1)} (not hudson.util.Secret)",
            "sinks": ["credentials"], "post": False, "score": 3,
        })

    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument("--min-score", type=int, default=0)
    args = parser.parse_args()

    results: list[tuple[Path, dict]] = []
    for root in args.roots:
        for path in sorted(root.rglob("*.java")):
            if "/test/" in str(path) or "/target/" in str(path):
                continue
            results.extend((root, finding) for finding in scan_file(path, root))

    results.sort(key=lambda item: -item[1]["score"])
    shown = 0
    for root, finding in results:
        if finding["score"] < args.min_score:
            continue
        shown += 1
        post = "" if finding["post"] else "  NO-POST"
        print(f"[{finding['score']:>2}] {finding['kind']:<22} {root.name}")
        print(f"     {finding['file']}:{finding['line']}  {finding['detail']}")
        print(f"     sinks={','.join(finding['sinks'])}{post}")
    print(f"\n{shown} shown / {len(results)} total", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
