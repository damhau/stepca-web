// Dashboard charts, drawn from the counts the server embeds in #dashboard-data
$(function () {
  "use strict";

  const data = JSON.parse(document.getElementById("dashboard-data").textContent);
  // Flot draws labels as HTML: escape the provisioner names and statuses
  const escapeHtml = text => $("<div>").text(text).html();
  const showEmpty = (selector, message) => {
    $(selector).empty().append($('<p class="text-muted text-center mt-5">').text(message));
  };

  const issued = Object.entries(data.issued_by_provisioner);
  if (!issued.length) {
    showEmpty("#bar-chart", "No certificates yet");
  } else {
    $.plot("#bar-chart", [{ data: issued.map(([, count], i) => [i + 1, count]), bars: { show: true } }], {
      grid: { borderWidth: 1, borderColor: "#f3f3f3", tickColor: "#f3f3f3" },
      series: { bars: { show: true, barWidth: 0.5, align: "center" } },
      colors: ["#3c8dbc"],
      xaxis: { ticks: issued.map(([name], i) => [i + 1, escapeHtml(name)]) },
      // Counts: whole numbers from zero
      yaxis: { min: 0, tickDecimals: 0 },
    });
  }

  const orders = Object.entries(data.acme_orders_by_status);
  // Flot's pie plugin fails on an empty series
  if (!orders.length) {
    showEmpty("#donut-chart", "No ACME orders yet");
  } else {
    const colours = { valid: "#3c8dbc", pending: "#f39c12", invalid: "#dd4b39", processing: "#0073b7", ready: "#00c0ef" };
    const series = orders.map(([status, count]) => ({
      label: status.charAt(0).toUpperCase() + status.slice(1),
      data: count,
      color: colours[status] || "#999999",
    }));
    $.plot("#donut-chart", series, {
      series: {
        pie: {
          show: true,
          radius: 1,
          innerRadius: 0.5,
          label: {
            show: true,
            radius: 2 / 3,
            threshold: 0.1,
            formatter: (label, slice) =>
              '<div class="dashboard-chart-label">' + escapeHtml(label) + "<br>" + Math.round(slice.percent) + "%</div>",
          },
        },
      },
      legend: { show: false },
    });
  }
});
