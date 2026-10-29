// Behaviour shared by every page. No inline event handlers: the Content-Security-Policy forbids them.
(function () {
  "use strict";

  // <form data-confirm="Question?">: ask before submitting
  document.addEventListener("submit", event => {
    const message = event.target.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });
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
