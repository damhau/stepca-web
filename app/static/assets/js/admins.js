// Admins page: the edit dialog changes an admin's type (the only field step-ca lets you change)
$(function () {
  "use strict";
  const modal = $("#editAdminModal");
  modal.on("show.bs.modal", event => {
    const button = $(event.relatedTarget);
    const admin = button.data("admin");
    document.getElementById("editAdminForm").action = modal.data("update-url").replace("__ID__", encodeURIComponent(admin.id));
    $("#editAdminSubject").val(admin.subject);
    $("#editAdminProvisioner").val(button.data("provisioner-name") || admin.provisioner_id);
    $("#editAdminType").val(String(admin.type === "SUPER_ADMIN" || admin.type === 2 ? 2 : 1));
  });
});
