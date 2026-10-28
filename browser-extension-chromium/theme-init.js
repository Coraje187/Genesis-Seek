// Applies the saved theme before the popup paints.
// Must live in its own file: Manifest V3 CSP blocks inline <script> tags.
try {
  var saved = localStorage.getItem("genesis_seek_theme");
  if (saved === "cream" || saved === "night") {
    document.documentElement.setAttribute("data-theme", saved);
  }
} catch (e) {}
