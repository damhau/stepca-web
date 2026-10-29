// Service control page: buttons with data-action POST to /step/service/<action>
(function () {
  "use strict";

  const panel = document.getElementById("service-control");
  const output = document.getElementById("serviceOutput");

  panel.addEventListener("click", event => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return;

    output.textContent = "Running " + action + "…";
    fetch(`/step/service/${action}`, { method: "POST", headers: { "X-CSRFToken": panel.dataset.csrf } })
      .then(response => {
        // An expired session answers with the login page, not JSON
        if (!(response.headers.get("Content-Type") || "").includes("application/json")) {
          throw new Error("the session has expired, reload the page and sign in again");
        }
        return response.json();
      })
      .then(data => { output.textContent = data.success ? data.output : "Error: " + data.error; })
      .catch(error => { output.textContent = "Error: " + error.message; });
  });
})();
