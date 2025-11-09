// src/security_ticker/static/security_ticker/js/ticker.js

document.addEventListener("DOMContentLoaded", function() {
  const track = document.getElementById("ticker-track");
  if (!track) {
    console.warn("Ticker track container not found");
    return;
  }

  fetch("/api/ticker/")
    .then(response => {
      if (!response.ok) {
        throw new Error("Network response was not ok: " + response.status);
      }
      return response.json();
    })
    .then(data => {
      const items = data.items || [];
      console.log("Ticker items:", items);  // debug log
      if (items.length === 0) {
        track.innerHTML = "<span class='ticker-item'>No current items</span>";
        return;
      }
      const fragment = document.createDocumentFragment();
      items.forEach(item => {
        const span = document.createElement("span");
        span.className = "ticker-item";

        // use the correct keys
        span.innerHTML = `<a href="${item.url || '#'}" target="_blank" rel="noopener">${item.title}</a> · ${item.subtitle || ""} · ${item.date || ""}`;
        fragment.appendChild(span);
      });

      track.appendChild(fragment);
      track.appendChild(fragment.cloneNode(true));
    })
    .catch(error => {
      console.error("Ticker fetch error:", error);
      track.innerHTML = "<span class='ticker-item'>Failed to load ticker data</span>";
    });
});
