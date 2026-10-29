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
      // No labels inside the slices: Flot positions them with inline styles, which the CSP forbids
      series: { pie: { show: true, radius: 1, innerRadius: 0.5, label: { show: false } } },
      legend: { show: false },
    });
    // A legend built with DOM calls; the swatch colour is set through the CSSOM, which the CSP allows
    const total = series.reduce((sum, slice) => sum + slice.data, 0);
    const legend = document.createElement("ul");
    legend.className = "chart-legend";
    for (const slice of series) {
      const item = document.createElement("li");
      const swatch = document.createElement("span");
      swatch.className = "chart-legend-swatch";
      swatch.style.backgroundColor = slice.color;
      item.append(swatch, document.createTextNode(`${slice.label}: ${slice.data} (${Math.round((100 * slice.data) / total)}%)`));
      legend.append(item);
    }
    document.getElementById("donut-chart").after(legend);
  }
});
