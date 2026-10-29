// Behaviour shared by every page. No inline event handlers: the Content-Security-Policy forbids them.
(function () {
  "use strict";

  // <form data-confirm="Question?">: ask before submitting
  document.addEventListener("submit", event => {
    const message = event.target.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });

  // A bar at the top of the window while the next page loads. Not for downloads, new tabs,
  // or links that scripts handle (modals, menus)
  const loading = () => document.body.classList.add("is-loading");
  document.addEventListener("click", event => {
    const link = event.target.closest("a[href]");
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (link.hasAttribute("download") || link.target === "_blank" || link.dataset.toggle || link.dataset.widget) return;
    const url = new URL(link.href, window.location.href);
    if (url.origin !== window.location.origin || (url.hash && url.pathname === window.location.pathname)) return;
    loading();
  });
  // Registered after the data-confirm handler, so a cancelled form doesn't show the bar
  document.addEventListener("submit", event => { if (!event.defaultPrevented) loading(); });
  // Back and forward restore pages from the cache with the bar still on
  window.addEventListener("pageshow", () => document.body.classList.remove("is-loading"));
})();

// Revoke dialog (x509/_revoke_modal.html): the button that opens it carries data-cert-id and data-cert-subject
$(function () {
  $("#revokeModal").on("show.bs.modal", event => {
    const button = $(event.relatedTarget);
    $("#modal_cert_id").val(button.data("cert-id"));
    $("#modal_cert_serial").text(button.data("cert-id"));
    $("#modal_cert_subject").text(button.data("cert-subject") || "");
  });
});
