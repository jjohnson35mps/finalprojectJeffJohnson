// src/security_ticker/static/security_ticker/js/ticker.js
document.addEventListener("DOMContentLoaded", function () {
  const track = document.getElementById("ticker-track");
  const statusEl = document.getElementById("ticker-status");
  if (!track) {
    console.warn("[ticker] #ticker-track not found");
    return;
  }

  fetch("/api/ticker/")
    .then((response) => {
      if (!response.ok) throw new Error("HTTP " + response.status);
      return response.json();
    })
    .then((data) => {
      const items = Array.isArray(data.items) ? data.items : [];
      console.debug("[ticker] source =", data.source || "unknown");
      console.debug("[ticker] items =", items);

      if (statusEl) statusEl.textContent = ""; // clear “Loading…”

      if (items.length === 0) {
        track.innerHTML = "<span class='ticker-item'>No current items</span>";
        return;
      }

      const fragment = document.createDocumentFragment();
      items.forEach((item) => {
        const span = document.createElement("span");
        span.className = "ticker-item";

        // Backend keys: title, date, link
        const title = item.title || "Item";
        const date = item.date ? ` · ${item.date}` : "";
        const link = item.link || "#";

        span.innerHTML = `<a href="${link}" target="_blank" rel="noopener">${title}</a>${date}`;
        fragment.appendChild(span);
      });

      track.innerHTML = "";           // reset
      track.appendChild(fragment);    // first copy
      track.appendChild(fragment.cloneNode(true)); // duplicate for seamless scroll
    })
    .catch((err) => {
      console.error("[ticker] fetch error:", err);
      if (statusEl) statusEl.textContent = "Failed to load";
      track.innerHTML = "<span class='ticker-item'>Failed to load ticker data</span>";
    });
});
