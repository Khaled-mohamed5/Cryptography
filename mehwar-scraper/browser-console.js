/* ============================================================================
 * تجميع طلبات "الأدبي" (الاسم + الرقم) من صفحة الأدمن
 * centerelmehwar.com/admin/Emp.aspx
 * ----------------------------------------------------------------------------
 * طريقة الاستخدام:
 *   1. افتح الموقع وسجّل دخول بحسابك، وادخل على صفحة Emp.aspx.
 *   2. اضغط F12 -> تبويب Console.
 *   3. انسخ الملف ده كله والصقه في الـ Console واضغط Enter.
 *   4. هيلف على كل الصفحات لوحده وينزّل ملف CSV يفتح على Excel.
 *
 * لو عايز تجمع كل الطلبات (مش الأدبي بس): غيّر collectAll لـ true.
 * لو الكلمة مكتوبة بشكل تاني في الجدول: زوّدها في مصفوفة keywords.
 * ========================================================================== */
(() => {
  "use strict";

  const CONFIG = {
    // الكلمات اللي بندوّر عليها في الصف عشان نعتبره "أدبي"
    keywords: [
      "أدبي", "ادبي", "أدبى", "ادبى", "الأدبي", "الادبي",
      "ادبي علوم", "لغات ادبي", "adaby", "adabi", "adaby", "literary", "arts",
    ],
    collectAll: false,   // true = هات كل الصفوف من غير فلترة
    maxPages: 300,       // أقصى عدد صفحات نلفها (حماية من اللوب اللانهائي)
    delayMs: 300,        // مهلة بين كل صفحة والتانية (متضغطش على السيرفر)
    excelSafePhones: true, // يحافظ على الصفر اللي في أول الرقم لما تفتح Excel
    fileName: "adaby-requests.csv",
  };

  /* ---------------------------------------------------------------- أدوات نص */

  const ARABIC_DIACRITICS = /[ً-ْٰـ]/g;

  function toEnglishDigits(s) {
    return String(s == null ? "" : s)
      .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660))
      .replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06f0));
  }

  // توحيد شكل الكلمة العربية عشان المقارنة تنجح مهما اتكتبت إزاي
  function norm(s) {
    return toEnglishDigits(s)
      .replace(/[‎‏ ]/g, " ")
      .replace(ARABIC_DIACRITICS, "")
      .replace(/[أإآٱ]/g, "ا")
      .replace(/ى/g, "ي")
      .replace(/ئ/g, "ي")
      .replace(/ؤ/g, "و")
      .replace(/ة/g, "ه")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  }

  function clean(s) {
    return String(s == null ? "" : s)
      .replace(/[‎‏ ]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  const NORM_KEYWORDS = CONFIG.keywords.map(norm).filter(Boolean);

  function matchesKeyword(text) {
    const n = norm(text);
    return NORM_KEYWORDS.some((k) => n.includes(k));
  }

  const arabicLetterCount = (s) => (String(s).match(/[ء-ي]/g) || []).length;

  /* ------------------------------------------------------------ استخراج أرقام */

  const DATE_LIKE = /\d{1,4}\s*[\/\-.]\s*\d{1,2}\s*[\/\-.]\s*\d{1,4}/;

  function normalizePhone(digits) {
    if (digits.startsWith("0020")) digits = "0" + digits.slice(4);
    else if (digits.startsWith("20") && digits.length >= 12) digits = "0" + digits.slice(2);
    if (digits.length === 10 && digits.startsWith("1")) digits = "0" + digits;
    return digits;
  }

  function extractPhones(text) {
    const t = toEnglishDigits(text).replace(/[‎‏]/g, "");
    const out = [];
    const re = /\+?\d[\d\s\-().]{5,}\d/g;
    let m;
    while ((m = re.exec(t)) !== null) {
      const raw = m[0];
      if (DATE_LIKE.test(raw)) continue;          // تجاهل التواريخ
      const digits = normalizePhone(raw.replace(/\D/g, ""));
      if (digits.length < 7 || digits.length > 15) continue;
      if (!out.includes(digits)) out.push(digits);
    }
    return out;
  }

  /* -------------------------------------------------- التعرف على أعمدة الجدول */

  const HEADER_HINTS = {
    name:  ["اسم", "الاسم", "اسم الطالب", "اسم المتقدم", "الطالب", "name", "student"],
    phone: ["رقم", "الرقم", "موبايل", "محمول", "تليفون", "الهاتف", "هاتف", "واتس",
            "phone", "mobile", "tel", "whats", "number"],
    track: ["شعبه", "الشعبه", "قسم", "القسم", "تخصص", "التخصص", "النوع", "نوع",
            "المرحله", "الصف", "المجموعه", "الماده", "type", "section", "grade",
            "department", "track", "subject"],
  };

  // كلمات لو ظهرت في خانة يبقى غالباً مش اسم شخص (شعبة/مرحلة/ملاحظات)
  const NAME_ANTI_HINTS = ["ادبي", "علمي", "شعبه", "قسم", "تخصص", "ثانويه",
                           "لغات", "مرحله", "مجموعه", "نوع", "ماده", "سنه"];

  function headerRole(text) {
    const n = norm(text);
    if (!n) return null;
    // الأولوية للتليفون عشان "رقم الموبايل" مايتحسبش اسم
    for (const role of ["phone", "track", "name"]) {
      if (HEADER_HINTS[role].some((h) => n.includes(norm(h)))) return role;
    }
    return null;
  }

  function cellsOf(row) {
    return Array.from(row.cells || []).map((c) => clean(c.innerText || c.textContent));
  }

  // بيدور على صف العناوين في أول 3 صفوف ويرجّع مكان كل عمود
  function detectColumns(table) {
    const rows = Array.from(table.rows || []).slice(0, 3);
    let best = null;
    for (const row of rows) {
      const texts = cellsOf(row);
      if (texts.length < 2) continue;
      const map = {};
      let score = 0;
      texts.forEach((t, i) => {
        const role = headerRole(t);
        if (role && map[role] === undefined) {
          map[role] = i;
          score++;
        }
      });
      if (score > 0 && (!best || score > best.score)) {
        best = { map, score, headerRow: row, headers: texts };
      }
    }
    return best;
  }

  /* -------------------------------------------------- تحويل الصف إلى سجل بيانات */

  function rowToRecord(texts, cols) {
    const joined = texts.join(" | ");
    const allPhones = extractPhones(joined);

    let name = "";
    let phone = "";
    let track = "";

    if (cols && cols.map.name !== undefined) name = texts[cols.map.name] || "";
    if (cols && cols.map.track !== undefined) track = texts[cols.map.track] || "";
    if (cols && cols.map.phone !== undefined) {
      phone = (extractPhones(texts[cols.map.phone] || "")[0]) || "";
    }

    // لو مفيش عناوين واضحة: خمّن — الاسم = الخانة اللي فيها أكتر حروف عربية وملهاش أرقام
    if (!name) {
      let bestIdx = -1, bestScore = 0;
      texts.forEach((t, i) => {
        if (cols && (i === cols.map.phone || i === cols.map.track)) return;
        if (/\d{4,}/.test(toEnglishDigits(t))) return;      // أرقام/سنين/تواريخ مش أسماء
        if (t.split(/\s+/).length > 6) return;               // جملة طويلة = ملاحظات
        let score = arabicLetterCount(t);
        const n = norm(t);
        if (NAME_ANTI_HINTS.some((h) => n.includes(h))) score *= 0.25;
        if (score > bestScore) { bestScore = score; bestIdx = i; }
      });
      if (bestIdx >= 0 && bestScore >= 3) name = texts[bestIdx];
    }

    if (!phone) phone = allPhones[0] || "";

    const extras = allPhones.filter((p) => p !== phone);
    return { name: clean(name), phone, extras, track: clean(track), rowText: joined };
  }

  function keep(record, cols) {
    if (CONFIG.collectAll) return true;
    // لو فيه عمود للشعبة/النوع نفلتر عليه هو بس، غير كده نفلتر على الصف كله
    if (cols && cols.map.track !== undefined && record.track) return matchesKeyword(record.track);
    return matchesKeyword(record.rowText);
  }

  /* ------------------------------------------------ استخراج السجلات من صفحة */

  function extractFromDoc(doc, pageNo, stats) {
    const records = [];
    const tables = Array.from(doc.querySelectorAll("table"));

    for (const table of tables) {
      const rows = Array.from(table.rows || []);
      if (rows.length < 2) continue;
      const cols = detectColumns(table);
      let taken = 0;

      for (const row of rows) {
        if (cols && row === cols.headerRow) continue;
        if (row.querySelector("th") && !row.querySelector("td")) continue; // صف عناوين
        const texts = cellsOf(row);
        if (texts.length < 2) continue;
        if (texts.every((t) => !t)) continue;

        const rec = rowToRecord(texts, cols);
        if (!rec.name && !rec.phone) continue;

        stats.scanned++;
        if (!keep(rec, cols)) continue;
        rec.page = pageNo;
        records.push(rec);
        taken++;
      }
      if (taken) stats.tables.add(table.id || table.className || "table");
    }
    return records;
  }

  /* --------------------------------------------------- التنقل بين صفحات الجدول */

  const POSTBACK_RE = /__doPostBack\(\s*['"](.*?)['"]\s*,\s*['"](.*?)['"]\s*\)/;

  function findPageLinks(doc) {
    const found = new Map(); // "Page$2" -> target
    doc.querySelectorAll('a[href*="__doPostBack"]').forEach((a) => {
      const href = a.getAttribute("href") || "";
      const m = POSTBACK_RE.exec(href.replace(/&#39;/g, "'").replace(/&quot;/g, '"'));
      if (!m) return;
      const [, target, arg] = m;
      if (/^Page\$/i.test(arg)) found.set(arg, target);
    });
    return found;
  }

  // رقم الصفحة الحالية بيبقى مكتوب من غير لينك (span) جوه شريط الترقيم
  function currentPageArgs(doc) {
    const args = new Set();
    doc.querySelectorAll('a[href*="Page$"]').forEach((a) => {
      const pager = a.closest("tr, td, div");
      if (!pager) return;
      pager.querySelectorAll("span").forEach((sp) => {
        const n = toEnglishDigits(clean(sp.textContent));
        if (/^\d+$/.test(n)) args.add("Page$" + n);
      });
    });
    return args;
  }

  function buildPayload(doc, target, argument) {
    const form = doc.querySelector("form");
    if (!form) throw new Error("مفيش <form> في الصفحة — الصفحة مش ASP.NET؟");
    const body = new URLSearchParams();
    form.querySelectorAll("input, select, textarea").forEach((el) => {
      const name = el.getAttribute("name");
      if (!name) return;
      const type = (el.getAttribute("type") || el.tagName).toLowerCase();
      if (["submit", "button", "image", "file", "reset"].includes(type)) return;
      if ((type === "checkbox" || type === "radio") && !el.checked) return;
      if (el.tagName === "SELECT") {
        const opts = Array.from(el.options || []).filter((o) => o.selected);
        (opts.length ? opts : []).forEach((o) => body.append(name, o.value));
        return;
      }
      body.append(name, el.value == null ? "" : el.value);
    });
    body.set("__EVENTTARGET", target);
    body.set("__EVENTARGUMENT", argument);
    body.delete("__ASYNCPOST");
    return body;
  }

  async function postback(doc, target, argument) {
    const form = doc.querySelector("form");
    const action = form.getAttribute("action") || location.href;
    const url = new URL(action, doc.baseURI || location.href).href;
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: buildPayload(doc, target, argument).toString(),
    });
    if (!res.ok) throw new Error("السيرفر رجّع " + res.status + " على صفحة " + argument);
    const text = await res.text();
    if (/^\d+\|/.test(text) && text.includes("|updatePanel|")) {
      throw new Error("الرد جه partial postback — كلّمني وأنا أظبط السكريبت.");
    }
    return new DOMParser().parseFromString(text, "text/html");
  }

  /* -------------------------------------------------------------- إخراج الملف */

  function csvCell(v) {
    const s = String(v == null ? "" : v);
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function phoneCell(p) {
    if (!p) return "";
    return CONFIG.excelSafePhones ? '="' + p + '"' : p;
  }

  function toCSV(records) {
    const head = ["م", "الاسم", "الرقم", "أرقام إضافية", "الشعبة / النوع", "الصفحة"];
    const lines = [head.map(csvCell).join(",")];
    records.forEach((r, i) => {
      lines.push([
        i + 1,
        csvCell(r.name),
        phoneCell(r.phone),
        csvCell((r.extras || []).join(" / ")),
        csvCell(r.track),
        r.page,
      ].join(","));
    });
    return lines.join("\r\n");
  }

  function download(fileName, text) {
    const blob = new Blob(["﻿" + text], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /* -------------------------------------------------------------------- تشغيل */

  (async function run() {
    const stats = { scanned: 0, tables: new Set() };
    const all = [];
    const seen = new Set();

    const push = (recs) => {
      for (const r of recs) {
        const key = (r.phone || "") + "|" + norm(r.name);
        if (key === "|") continue;
        if (seen.has(key)) continue;
        seen.add(key);
        all.push(r);
      }
    };

    console.log("%c⏳ بجمع الطلبات…", "font-size:14px");

    let doc = document;
    let pageNo = 1;
    push(extractFromDoc(doc, pageNo, stats));

    const visited = new Set(currentPageArgs(doc));
    const queue = [];
    const seenArgs = new Set(visited);

    const enqueue = (d) => {
      for (const [arg, target] of findPageLinks(d)) {
        if (seenArgs.has(arg)) continue;
        seenArgs.add(arg);
        queue.push({ arg, target });
      }
    };
    enqueue(doc);

    while (queue.length && pageNo < CONFIG.maxPages) {
      const { arg, target } = queue.shift();
      pageNo++;
      try {
        console.log("  → " + arg.replace("Page$", "صفحة "));
        const next = await postback(doc, target, arg);
        push(extractFromDoc(next, pageNo, stats));
        enqueue(next);
        doc = next;                 // ViewState الجديد لازم يتاخد من آخر صفحة
      } catch (e) {
        console.warn("مشكلة في " + arg + ": " + e.message);
      }
      await sleep(CONFIG.delayMs);
    }

    window.__MEHWAR__ = all;

    console.log(
      "%c✅ خلص: " + all.length + " سجل من " + pageNo + " صفحة " +
      "(اتفحص " + stats.scanned + " صف)",
      "font-size:14px;color:green"
    );

    if (!all.length) {
      console.warn(
        "ملقيتش أي صف مطابق.\n" +
        "• جرّب CONFIG.collectAll = true عشان تشوف السكريبت بيقرا إيه.\n" +
        "• أو زوّد الكلمة زي ما هي مكتوبة في الجدول في CONFIG.keywords."
      );
      return;
    }

    console.table(all.map((r) => ({ الاسم: r.name, الرقم: r.phone, الشعبة: r.track })));
    download(CONFIG.fileName, toCSV(all));
    console.log("📁 نزّلت الملف: " + CONFIG.fileName + "  (البيانات كمان في window.__MEHWAR__)");
  })();
})();
