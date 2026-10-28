// Search, sort and paging for tables marked with data-table-tools.
// No dependency; cell contents are only ever read as text, never inserted as HTML.
(function () {
  "use strict";

  const PAGE_SIZE = 50;

  // A cell sorts by its data-sort-value (e.g. an ISO date) when it has one, else by its text
  function cellText(row, index) {
    const cell = row.cells[index];
    if (!cell) return "";
    return cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : cell.textContent.trim();
  }

  // Numeric collation compares digit runs by value, so 39-digit serials sort exactly
  function compare(a, b) {
    return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
  }

  function enhance(table) {
    const body = table.tBodies[0];
    if (!body) return;
    // Rows spanning every column are "no data" placeholders, not data
    const rows = Array.from(body.rows).filter(r => !(r.cells.length === 1 && r.cells[0].colSpan > 1));
    if (rows.length === 0) return;
    let filtered = rows, page = 0, sortIndex = -1, sortAsc = true;

    const search = document.createElement("input");
    search.type = "search";
    search.className = "form-control form-control-sm";
    search.placeholder = "Search…";
    search.setAttribute("aria-label", "Search the table");
    const info = document.createElement("small");
    info.className = "text-muted";
    const prev = document.createElement("button"), next = document.createElement("button");
    for (const [button, label] of [[prev, "‹ Previous"], [next, "Next ›"]]) {
      button.type = "button";
      button.className = "btn btn-sm btn-outline-secondary ml-1";
      button.textContent = label;
    }
    const top = document.createElement("div");
    top.className = "d-flex align-items-center p-2";
    search.style.maxWidth = "320px";
    top.append(search);
    const bottom = document.createElement("div");
    bottom.className = "d-flex align-items-center justify-content-end p-2";
    bottom.append(info, prev, next);
    table.before(top);
    table.after(bottom);

    function render() {
      const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
      page = Math.min(page, pages - 1);
      const start = page * PAGE_SIZE, end = Math.min(start + PAGE_SIZE, filtered.length);
      rows.forEach(r => { r.style.display = "none"; });
      filtered.slice(start, end).forEach(r => { r.style.display = ""; body.appendChild(r); });
      info.textContent = filtered.length ? `${start + 1}–${end} of ${filtered.length}` + (filtered.length !== rows.length ? ` (${rows.length} total)` : "") : "No match";
      prev.disabled = page === 0;
      next.disabled = page >= pages - 1;
      bottom.style.display = rows.length > PAGE_SIZE || filtered.length !== rows.length ? "" : "none";
    }

    function applyFilterAndSort() {
      const terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
      filtered = rows.filter(r => terms.every(t => r.textContent.toLowerCase().includes(t)));
      if (sortIndex >= 0) {
        filtered.sort((a, b) => (sortAsc ? 1 : -1) * compare(cellText(a, sortIndex), cellText(b, sortIndex)));
      }
      render();
    }

    Array.from(table.tHead ? table.tHead.rows[0].cells : []).forEach((th, index) => {
      if (th.hasAttribute("data-no-sort")) return;
      th.style.cursor = "pointer";
      th.setAttribute("role", "button");
      th.title = "Sort";
      th.addEventListener("click", () => {
        sortAsc = sortIndex === index ? !sortAsc : true;
        sortIndex = index;
        table.querySelectorAll("th[aria-sort]").forEach(h => h.removeAttribute("aria-sort"));
        th.setAttribute("aria-sort", sortAsc ? "ascending" : "descending");
        applyFilterAndSort();
      });
    });
    search.addEventListener("input", () => { page = 0; applyFilterAndSort(); });
    prev.addEventListener("click", () => { page -= 1; render(); });
    next.addEventListener("click", () => { page += 1; render(); });
    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("table[data-table-tools]").forEach(enhance);
  });
})();
