// Sign form: load a CSR file into the text field, and show what the CSR asks for before signing
$(function () {
  "use strict";

  const form = document.getElementById("signForm");
  if (!form) return;  // operators only
  const text = document.getElementById("csr_pem");
  const file = document.getElementById("csr_file");
  const preview = document.getElementById("csrPreview");

  function row(label, value) {
    const line = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = label + ": ";
    line.append(name, document.createTextNode(value));
    return line;
  }

  function show(data) {
    preview.replaceChildren();
    preview.hidden = false;
    preview.classList.toggle("alert-danger", Boolean(data.error) || data.signature_valid === false);
    if (data.error) {
      preview.textContent = data.error;
      return;
    }
    preview.append(
      row("Subject", data.subject || "(empty)"),
      row("Names", data.sans.length ? data.sans.join(", ") : "none"),
      row("Key", data.key),
    );
    if (!data.signature_valid) preview.append(row("Signature", "not valid: step-ca will refuse this CSR"));
  }

  let timer = null;
  function refresh() {
    clearTimeout(timer);
    if (!text.value.trim()) {
      preview.hidden = true;
      return;
    }
    timer = setTimeout(() => {
      fetch(form.dataset.previewUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": form.dataset.csrf },
        body: JSON.stringify({ csr_pem: text.value }),
      })
        .then(response => response.json())
        .then(show)
        .catch(() => show({ error: "Could not read the CSR (has the session expired?)" }));
    }, 300);
  }

  text.addEventListener("input", refresh);
  file.addEventListener("change", () => {
    const chosen = file.files[0];
    if (!chosen) return;
    file.nextElementSibling.textContent = chosen.name;
    chosen.text().then(content => {
      text.value = content;
      refresh();
    });
  });
});
