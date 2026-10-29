// Provisioners page
$(function () {
  "use strict";

  $("#viewModal").on("show.bs.modal", event => {
    const prov = $(event.relatedTarget).data("prov");
    // textContent: provisioner fields (templates, names) are never interpreted as HTML
    document.getElementById("provJson").textContent = prov ? JSON.stringify(prov, null, 2) : "Failed to load provisioner data.";
  });

  // Create form, only rendered for admins: only the fields of the selected type are shown, required and submitted
  const selector = document.getElementById("provType");
  if (!selector) return;
  function toggleFields() {
    for (const [id, active] of [["acmeFields", selector.value === "ACME"], ["jwkFields", selector.value === "JWK"]]) {
      const block = document.getElementById(id);
      block.hidden = !active;
      block.querySelectorAll("input").forEach(input => { input.disabled = !active; });
    }
  }
  selector.addEventListener("change", toggleFields);
  toggleFields();
});
