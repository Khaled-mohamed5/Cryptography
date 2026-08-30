#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
تجميع طلبات "الأدبي" (الاسم + الرقم) من صفحة الأدمن.

مثال:
    python3 collect.py --user اسم_المستخدم --password الباسورد -o adaby.csv
    python3 collect.py --cookie "ASP.NET_SessionId=...; .ASPXAUTH=..." --all
    python3 collect.py --keyword "أدبي" --dump-html debug/

السكريبت بيتعامل مع صفحات ASP.NET WebForms:
بيقرا الـ __VIEWSTATE ويعمل postback عشان يلف على كل صفحات الجدول.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("محتاج تثبّت المكتبات الأول:  pip install -r requirements.txt")


DEFAULT_URL = "https://centerelmehwar.com/admin/Emp.aspx"

DEFAULT_KEYWORDS = [
    "أدبي", "ادبي", "أدبى", "ادبى", "الأدبي", "الادبي",
    "adaby", "adabi", "literary", "arts",
]

HEADER_HINTS = {
    "phone": ["رقم", "الرقم", "موبايل", "محمول", "تليفون", "الهاتف", "هاتف",
              "واتس", "phone", "mobile", "tel", "whats", "number"],
    "track": ["شعبه", "الشعبه", "قسم", "القسم", "تخصص", "التخصص", "النوع", "نوع",
              "المرحله", "الصف", "المجموعه", "الماده", "type", "section",
              "grade", "department", "track", "subject"],
    "name":  ["اسم", "الاسم", "الطالب", "المتقدم", "name", "student"],
}

# كلمات لو ظهرت في خانة يبقى غالباً مش اسم شخص (شعبة/مرحلة/ملاحظات)
NAME_ANTI_HINTS = ["ادبي", "علمي", "شعبه", "قسم", "تخصص", "ثانويه", "لغات",
                   "مرحله", "مجموعه", "نوع", "ماده", "سنه"]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


# ------------------------------------------------------------------ أدوات نص

ARABIC_DIACRITICS = re.compile(r"[ً-ْٰـ]")
BIDI_MARKS = re.compile(r"[‎‏​ ]")


def to_english_digits(s: str) -> str:
    out = []
    for ch in str(s or ""):
        code = ord(ch)
        if 0x0660 <= code <= 0x0669:
            out.append(chr(code - 0x0660 + ord("0")))
        elif 0x06F0 <= code <= 0x06F9:
            out.append(chr(code - 0x06F0 + ord("0")))
        else:
            out.append(ch)
    return "".join(out)


def clean(s: str) -> str:
    return re.sub(r"\s+", " ", BIDI_MARKS.sub(" ", str(s or ""))).strip()


def norm(s: str) -> str:
    """توحيد شكل الكلمة العربية عشان المقارنة تنجح مهما اتكتبت إزاي."""
    s = to_english_digits(BIDI_MARKS.sub(" ", str(s or "")))
    s = ARABIC_DIACRITICS.sub("", s)
    s = re.sub(r"[أإآٱ]", "ا", s)
    s = s.replace("ى", "ي").replace("ئ", "ي").replace("ؤ", "و").replace("ة", "ه")
    return re.sub(r"\s+", " ", s).strip().lower()


def arabic_letters(s: str) -> int:
    return len(re.findall(r"[ء-ي]", str(s or "")))


# --------------------------------------------------------------- أرقام تليفون

DATE_LIKE = re.compile(r"\d{1,4}\s*[/\-.]\s*\d{1,2}\s*[/\-.]\s*\d{1,4}")
PHONE_CANDIDATE = re.compile(r"\+?\d[\d\s\-().]{5,}\d")


def normalize_phone(digits: str) -> str:
    if digits.startswith("0020"):
        digits = "0" + digits[4:]
    elif digits.startswith("20") and len(digits) >= 12:
        digits = "0" + digits[2:]
    if len(digits) == 10 and digits.startswith("1"):
        digits = "0" + digits
    return digits


def extract_phones(text: str) -> list[str]:
    text = to_english_digits(BIDI_MARKS.sub(" ", str(text or "")))
    found: list[str] = []
    for match in PHONE_CANDIDATE.finditer(text):
        raw = match.group(0)
        if DATE_LIKE.search(raw):
            continue
        digits = normalize_phone(re.sub(r"\D", "", raw))
        if not 7 <= len(digits) <= 15:
            continue
        if digits not in found:
            found.append(digits)
    return found


# ------------------------------------------------------------- قراءة الجداول

def own_rows(table):
    return [tr for tr in table.find_all("tr") if tr.find_parent("table") is table]


def own_cells(tr):
    return [c for c in tr.find_all(["td", "th"]) if c.find_parent("tr") is tr]


def cell_texts(tr) -> list[str]:
    return [clean(c.get_text(" ", strip=True)) for c in own_cells(tr)]


def header_role(text: str) -> str | None:
    n = norm(text)
    if not n:
        return None
    for role in ("phone", "track", "name"):   # التليفون الأول عشان "رقم الموبايل"
        if any(norm(h) in n for h in HEADER_HINTS[role]):
            return role
    return None


def detect_columns(table):
    """بيدور على صف العناوين في أول 3 صفوف ويرجّع مكان كل عمود."""
    best = None
    for tr in own_rows(table)[:3]:
        texts = cell_texts(tr)
        if len(texts) < 2:
            continue
        mapping, score = {}, 0
        for i, t in enumerate(texts):
            role = header_role(t)
            if role and role not in mapping:
                mapping[role] = i
                score += 1
        if score and (best is None or score > best["score"]):
            best = {"map": mapping, "score": score, "header": tr, "headers": texts}
    return best


def row_to_record(texts: list[str], cols) -> dict:
    joined = " | ".join(texts)
    all_phones = extract_phones(joined)
    mapping = cols["map"] if cols else {}

    name = texts[mapping["name"]] if "name" in mapping and mapping["name"] < len(texts) else ""
    track = texts[mapping["track"]] if "track" in mapping and mapping["track"] < len(texts) else ""
    phone = ""
    if "phone" in mapping and mapping["phone"] < len(texts):
        p = extract_phones(texts[mapping["phone"]])
        phone = p[0] if p else ""

    if not name:  # تخمين: الخانة اللي فيها أكتر حروف عربية ومفيهاش أرقام طويلة
        best_i, best_score = -1, 0.0
        for i, t in enumerate(texts):
            if i in (mapping.get("phone"), mapping.get("track")):
                continue
            if re.search(r"\d{4,}", to_english_digits(t)):   # أرقام/سنين/تواريخ مش أسماء
                continue
            if len(t.split()) > 6:                            # جملة طويلة = ملاحظات
                continue
            score = float(arabic_letters(t))
            if any(h in norm(t) for h in NAME_ANTI_HINTS):
                score *= 0.25
            if score > best_score:
                best_i, best_score = i, score
        if best_i >= 0 and best_score >= 3:
            name = texts[best_i]

    if not phone and all_phones:
        phone = all_phones[0]

    return {
        "name": clean(name),
        "phone": phone,
        "extras": [p for p in all_phones if p != phone],
        "track": clean(track),
        "row_text": joined,
    }


def extract_records(soup, page_no: int, keywords: list[str], collect_all: bool, stats: dict):
    records = []
    for table in soup.find_all("table"):
        rows = own_rows(table)
        if len(rows) < 2:
            continue
        cols = detect_columns(table)
        for tr in rows:
            if cols and tr is cols["header"]:
                continue
            if own_cells(tr) and all(c.name == "th" for c in own_cells(tr)):
                continue
            texts = cell_texts(tr)
            if len(texts) < 2 or not any(texts):
                continue

            rec = row_to_record(texts, cols)
            if not rec["name"] and not rec["phone"]:
                continue
            stats["scanned"] += 1

            if not collect_all:
                haystack = rec["track"] if (cols and "track" in cols["map"] and rec["track"]) \
                    else rec["row_text"]
                if not any(k in norm(haystack) for k in keywords):
                    continue

            rec["page"] = page_no
            records.append(rec)
    return records


# ------------------------------------------------------- ASP.NET postbacks

POSTBACK_RE = re.compile(r"__doPostBack\(\s*['\"](.*?)['\"]\s*,\s*['\"](.*?)['\"]\s*\)")


def form_payload(soup, target: str, argument: str) -> dict:
    form = soup.find("form")
    if form is None:
        raise RuntimeError("مفيش <form> في الصفحة — يمكن اتسجّل خروج أو الرابط غلط.")
    data: dict[str, str] = {}
    for el in form.find_all(["input", "select", "textarea"]):
        name = el.get("name")
        if not name:
            continue
        tag = el.name.lower()
        typ = (el.get("type") or "").lower()
        if typ in ("submit", "button", "image", "file", "reset"):
            continue
        if typ in ("checkbox", "radio") and not el.has_attr("checked"):
            continue
        if tag == "select":
            opt = el.find("option", selected=True) or el.find("option")
            data[name] = (opt.get("value", opt.get_text(strip=True)) if opt else "")
        elif tag == "textarea":
            data[name] = el.get_text()
        else:
            data[name] = el.get("value", "")
    data["__EVENTTARGET"] = target
    data["__EVENTARGUMENT"] = argument
    data.pop("__ASYNCPOST", None)
    return data


def page_links(soup) -> dict[str, str]:
    """كل لينكات ترقيم الصفحات: {"Page$2": "اسم الجريد"}"""
    found: dict[str, str] = {}
    for a in soup.find_all("a", href=True):
        m = POSTBACK_RE.search(a["href"])
        if m and m.group(2).lower().startswith("page$"):
            found[m.group(2)] = m.group(1)
    return found


def current_page_args(soup) -> set[str]:
    args = set()
    for a in soup.find_all("a", href=True):
        if "Page$" not in a["href"]:
            continue
        pager = a.find_parent("tr") or a.find_parent("td") or a.find_parent("div")
        if not pager:
            continue
        for span in pager.find_all("span"):
            txt = to_english_digits(clean(span.get_text()))
            if txt.isdigit():
                args.add("Page$" + txt)
    return args


# --------------------------------------------------------------- تسجيل الدخول

def find_login_form(soup):
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": re.compile("^password$", re.I)}):
            return form
    return None


def do_login(session, page_url: str, soup, username: str, password: str, verbose=True):
    form = find_login_form(soup)
    if form is None:
        return soup  # مش محتاج لوجين

    pwd_input = form.find("input", attrs={"type": re.compile("^password$", re.I)})
    inputs = form.find_all("input")
    user_input = None
    for el in inputs:
        if el is pwd_input:
            break
        typ = (el.get("type") or "text").lower()
        if typ in ("text", "email", "tel"):
            user_input = el          # آخر خانة نص قبل الباسورد
    if user_input is None:
        for el in inputs:
            ident = norm((el.get("name") or "") + " " + (el.get("id") or ""))
            if any(k in ident for k in ("user", "email", "login", "mail")):
                user_input = el
                break
    if user_input is None or not pwd_input.get("name"):
        raise RuntimeError("ملقيتش خانات اللوجين — استخدم --cookie بدل اليوزر والباسورد.")

    data = form_payload(soup, "", "")
    data[user_input["name"]] = username
    data[pwd_input["name"]] = password

    submit = form.find("input", attrs={"type": re.compile("^submit$", re.I)}) \
        or form.find("button", attrs={"type": re.compile("^submit$", re.I)})
    if submit is not None and submit.get("name"):
        data[submit["name"]] = submit.get("value", "Login")

    action = urljoin(page_url, form.get("action") or page_url)
    if verbose:
        print("🔐 بسجّل دخول…")
    res = session.post(action, data=data, timeout=40)
    res.raise_for_status()
    return BeautifulSoup(res.text, "html.parser")


# ----------------------------------------------------------------- الإخراج

def write_csv(path: Path, records: list[dict], excel_safe: bool):
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["م", "الاسم", "الرقم", "أرقام إضافية", "الشعبة / النوع", "الصفحة"])
        for i, r in enumerate(records, 1):
            phone = r["phone"]
            if excel_safe and phone:
                phone = f'="{phone}"'
            writer.writerow([i, r["name"], phone, " / ".join(r["extras"]),
                             r["track"], r.get("page", "")])


def write_xlsx(path: Path, records: list[dict]) -> bool:
    try:
        from openpyxl import Workbook
    except ImportError:
        return False
    wb = Workbook()
    ws = wb.active
    ws.title = "الطلبات"
    ws.append(["م", "الاسم", "الرقم", "أرقام إضافية", "الشعبة / النوع", "الصفحة"])
    for i, r in enumerate(records, 1):
        ws.append([i, r["name"], r["phone"], " / ".join(r["extras"]),
                   r["track"], r.get("page", "")])
    for cell in ws["C"]:
        cell.number_format = "@"        # الرقم كنص عشان الصفر مايختفيش
    ws.sheet_view.rightToLeft = True
    wb.save(path)
    return True


# ------------------------------------------------------------------ التشغيل

def main() -> int:
    ap = argparse.ArgumentParser(description="تجميع أسماء وأرقام طلبات الأدبي")
    ap.add_argument("--url", default=os.environ.get("MEHWAR_URL", DEFAULT_URL),
                    help="رابط الصفحة اللي فيها الجدول")
    ap.add_argument("--user", default=os.environ.get("MEHWAR_USER"))
    ap.add_argument("--password", default=os.environ.get("MEHWAR_PASS"))
    ap.add_argument("--cookie", default=os.environ.get("MEHWAR_COOKIE"),
                    help="بديل اللوجين: الكوكيز من المتصفح بعد ما تسجّل دخول")
    ap.add_argument("--keyword", action="append", default=None,
                    help="كلمة الفلترة (تتكرر أكتر من مرة)")
    ap.add_argument("--all", action="store_true", help="هات كل الطلبات من غير فلترة")
    ap.add_argument("-o", "--out", default="adaby-requests.csv")
    ap.add_argument("--xlsx", action="store_true", help="اطلع ملف Excel كمان")
    ap.add_argument("--max-pages", type=int, default=300)
    ap.add_argument("--delay", type=float, default=0.4, help="ثواني بين كل صفحة والتانية")
    ap.add_argument("--dump-html", metavar="DIR",
                    help="احفظ HTML كل صفحة (للتشخيص لو الأعمدة طلعت غلط)")
    ap.add_argument("--no-excel-safe", action="store_true",
                    help="اكتب الرقم خام من غير ='...' حوله")
    args = ap.parse_args()

    keywords = [norm(k) for k in (args.keyword or DEFAULT_KEYWORDS) if norm(k)]
    dump_dir = Path(args.dump_html) if args.dump_html else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Accept-Language": "ar,en;q=0.8"})
    if args.cookie:
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                session.cookies.set(k.strip(), v.strip())

    print(f"🌐 بفتح {args.url}")
    res = session.get(args.url, timeout=40)
    res.raise_for_status()
    soup = BeautifulSoup(res.text, "html.parser")

    if find_login_form(soup) is not None and not args.cookie:
        user = args.user or input("اسم المستخدم: ")
        pwd = args.password or getpass.getpass("الباسورد: ")
        soup = do_login(session, res.url, soup, user, pwd)
        res = session.get(args.url, timeout=40)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        if find_login_form(soup) is not None:
            print("❌ اللوجين فشل — اتأكد من البيانات أو استخدم --cookie", file=sys.stderr)
            return 2
    elif find_login_form(soup) is not None:
        print("❌ الكوكيز مش شغالة/منتهية — سجّل دخول تاني وهات كوكيز جديدة", file=sys.stderr)
        return 2

    stats = {"scanned": 0}
    records: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(new_records):
        for r in new_records:
            key = (r["phone"], norm(r["name"]))
            if key == ("", "") or key in seen:
                continue
            seen.add(key)
            records.append(r)

    page_no = 1
    if dump_dir:
        (dump_dir / f"page-{page_no:03d}.html").write_text(res.text, encoding="utf-8")
    add(extract_records(soup, page_no, keywords, args.all, stats))

    queued_args = set(current_page_args(soup))
    queue: list[tuple[str, str]] = []
    for arg, target in page_links(soup).items():
        if arg not in queued_args:
            queued_args.add(arg)
            queue.append((arg, target))

    while queue and page_no < args.max_pages:
        arg, target = queue.pop(0)
        page_no += 1
        print(f"  → {arg.replace('Page$', 'صفحة ')}")
        try:
            data = form_payload(soup, target, arg)
            action = urljoin(res.url, soup.find("form").get("action") or res.url)
            res = session.post(action, data=data, timeout=60)
            res.raise_for_status()
            if dump_dir:
                (dump_dir / f"page-{page_no:03d}.html").write_text(res.text, encoding="utf-8")
            soup = BeautifulSoup(res.text, "html.parser")   # ViewState الجديد
            add(extract_records(soup, page_no, keywords, args.all, stats))
            for a, t in page_links(soup).items():
                if a not in queued_args:
                    queued_args.add(a)
                    queue.append((a, t))
        except Exception as exc:                      # noqa: BLE001
            print(f"⚠️  مشكلة في {arg}: {exc}", file=sys.stderr)
        time.sleep(args.delay)

    print(f"\n✅ اتجمع {len(records)} سجل من {page_no} صفحة (اتفحص {stats['scanned']} صف)")
    if not records:
        print("ملقيتش أي صف مطابق. جرّب --all عشان تشوف الجدول بيتقرا إزاي، "
              "أو --keyword بالكلمة زي ما هي مكتوبة في الموقع.", file=sys.stderr)
        return 1

    out = Path(args.out)
    write_csv(out, records, excel_safe=not args.no_excel_safe)
    print(f"📁 {out}")
    if args.xlsx:
        xlsx_path = out.with_suffix(".xlsx")
        if write_xlsx(xlsx_path, records):
            print(f"📁 {xlsx_path}")
        else:
            print("ℹ️  عايز openpyxl عشان ملف الإكسل:  pip install openpyxl")

    for r in records[:10]:
        print(f"   {r['name']:<30} {r['phone']}")
    if len(records) > 10:
        print(f"   … و {len(records) - 10} كمان")
    return 0


if __name__ == "__main__":
    sys.exit(main())
