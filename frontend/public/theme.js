// The theme chosen in the app ("light", "dark"), or the system's
;(function () {
  var chosen = null
  try {
    chosen = localStorage.getItem("theme")
  } catch (e) {
    // Storage may be blocked: follow the system
  }
  var dark = chosen ? chosen === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches
  document.documentElement.classList.toggle("dark", dark)
})()
