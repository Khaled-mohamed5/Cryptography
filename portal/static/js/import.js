// Data Import: post the pasted supplier document and show the parsed result.
(function () {
  "use strict";

  function show(out, text, ok) {
    out.textContent = text;
    out.className = ok ? "" : "bad";
  }

  async function doImport() {
    const btn = document.getElementById("go");
    const out = document.getElementById("out");
    btn.disabled = true;
    show(out, "Importing…", true);
    try {
      const res = await fetch("/api/catalog/import", {
        method: "POST",
        headers: { "Content-Type": "application/xml" },
        body: document.getElementById("xml").value,
      });
      const txt = await res.text();
      let pretty = txt;
      try {
        pretty = JSON.stringify(JSON.parse(txt), null, 2);
      } catch (e) {
        // Not JSON; show whatever came back verbatim.
      }
      show(out, pretty, res.ok);
    } catch (e) {
      show(out, "The import request could not be sent: " + e.message, false);
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("go").addEventListener("click", doImport);
  });
})();
