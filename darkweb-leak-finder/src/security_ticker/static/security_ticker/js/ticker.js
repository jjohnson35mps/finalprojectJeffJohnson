// INF601 - Advanced Programming in Python
// Jeff Johnson
// Final Project
// src/security_ticker/static/security_ticker/js/ticker.js
//
// Purpose:
//   Fetch a small set of "known exploited vulnerabilities" (KEV) or
//   similar items from the backend and render them into a horizontally
//   scrolling ticker at the top of the app.
//
// OWASP Top 10 touchpoints:
//   - A03: Injection / A05: Security Misconfiguration
//       * We never use untrusted data in innerHTML.
//       * We validate ticker link URLs before assigning href.
//   - A09: Security Logging & Monitoring
//       * We log basic errors to the console without leaking secrets.
//
// Assumptions:
//   - Backend endpoint: GET /api/ticker/ -> { items: [...], source: "..." }
//   - Each item: { title: string, date: string, link: string }

document.addEventListener("DOMContentLoaded", function () {
  // ---------------------------
  // Element lookups
  // ---------------------------
  const track = document.getElementById("ticker-track");
  const statusEl = document.getElementById("ticker-status");

  if (!track) {
    console.warn("[ticker] #ticker-track not found");
    return;
  }

  // ---------------------------
  // Small helper: URL safety
  // ---------------------------
  /**
   * Determine whether a link is safe to use in href.
   *
   * Security notes (OWASP A03/A05):
   *  - Only allow http/https URLs.
   *  - Reject javascript:, data:, etc. to avoid XSS via protocol abuse.
   */
  function isSafeHttpUrl(url) {
    if (typeof url !== "string" || !url) return false;
    try {
      const u = new URL(url, window.location.origin);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch (e) {
      return false;
    }
  }

  // ---------------------------
  // Fetch ticker data from API
  // ---------------------------
  fetch("/api/ticker/", { credentials: "same-origin" })
    .then((response) => {
      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }
      return response.json();
    })
    .then((data) => {
      const items = Array.isArray(data.items) ? data.items : [];

      // Log only minimal info (A09: avoid leaking sensitive details)
      console.debug(
        "[ticker] source = %s, count = %d",
        data.source || "unknown",
        items.length
      );

      // Clear "Loading..." message if present
      if (statusEl) {
        statusEl.textContent = "";
      }

      // ---------------------------
      // Handle empty state
      // ---------------------------
      if (items.length === 0) {
        const span = document.createElement("span");
        span.className = "ticker-item";
        span.textContent = "No current items";
        track.replaceChildren(span);
        return;
      }

      // ---------------------------
      // Build DOM fragment safely
      // ---------------------------
      const fragment = document.createDocumentFragment();

      items.forEach((item) => {
        const span = document.createElement("span");
        span.className = "ticker-item";

        // Backend keys: title, date, link
        const rawTitle = typeof item.title === "string" ? item.title : "";
        const title = rawTitle || "Item";

        const dateStr =
          typeof item.date === "string" && item.date.trim()
            ? ` · ${item.date.trim()}`
            : "";

        const rawLink = typeof item.link === "string" ? item.link : "";
        const safeLink = isSafeHttpUrl(rawLink) ? rawLink : "#";

        // <a href="..." target="_blank" rel="noopener noreferrer">Title</a> · YYYY-MM-DD
        const anchor = document.createElement("a");
        anchor.href = safeLink;
        anchor.target = "_blank";
        anchor.rel = "noopener noreferrer"; // avoid reverse tabnabbing
        anchor.textContent = title;

        span.appendChild(anchor);

        if (dateStr) {
          const dateNode = document.createTextNode(dateStr);
          span.appendChild(dateNode);
        }

        fragment.appendChild(span);
      });

      // ---------------------------
      // Render & duplicate for scroll
      // ---------------------------
      track.replaceChildren(fragment);

      // Clone the track contents once to create seamless scrolling
      const clone = track.cloneNode(true);
      // We only need its children appended to the real track
      while (clone.firstChild) {
        track.appendChild(clone.firstChild);
      }
    })
    .catch((err) => {
      console.error("[ticker] fetch error:", err);

      if (statusEl) {
        statusEl.textContent = "Failed to load";
      }

      const span = document.createElement("span");
      span.className = "ticker-item";
      span.textContent = "Failed to load ticker data";
      track.replaceChildren(span);
    });
});
