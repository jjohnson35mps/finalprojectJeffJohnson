// ------------------------------------------------------------
// ThreatMap front-end (Leaflet + heat + source selector + sidebar)
//
// Responsibilities:
//   - Build the Leaflet map & tile layers
//   - Fetch heatmap points from /threatmap/api/points/
//   - Render heat layer + hover tooltips + sidebar summary
//   - Auto-refresh based on server-provided interval
//
// OWASP Top 10 touchpoints:
//   - A01 (Broken Access Control):
//       This script assumes the API endpoint is already protected
//       by server-side auth (e.g., @login_required). It does not
//       bypass or manage access control itself.
//   - A03/A05 (Injection / Security Misconfiguration):
//       Avoids injecting untrusted values into innerHTML where
//       possible (particularly in updateSidebar), using DOM APIs
//       instead to reduce XSS risk if backend data were compromised.
//   - A09 (Security Logging & Monitoring):
//       Uses console logging for client-side debug only; sensitive
//       data (tokens, raw responses) should be logged only on the
//       server where appropriate.
// ------------------------------------------------------------
(function () {
  // ----------------------------------------------------------
  // Configuration & mutable state
  // ----------------------------------------------------------
  const elId = "tm-world-map";                              // Map container ID
  const API  = window.THREATMAP_API || "/threatmap/api/points/";
  const sourceSel = document.getElementById("tm-radar-source");

  let heatLayerRef = null;  // current Leaflet heat layer
  let hoverLayerRefs = [];  // invisible markers for tooltips
  let refreshTimer = null;  // auto-refresh interval handle

  // ----------------------------------------------------------
  // API URL builder
  // ----------------------------------------------------------
  /**
   * Build the API URL, including ?source=... if a dropdown is present/selected.
   * Note: Uses window.location.origin as base to avoid surprises with relative
   * paths; API endpoint is expected to be same-origin (mitigates CORS confusion).
   */
  function apiUrl() {
    const url = new URL(API, window.location.origin);
    if (sourceSel && sourceSel.value) {
      url.searchParams.set("source", sourceSel.value);
    }
    return url.toString();
  }

  // ----------------------------------------------------------
  // Fetch + normalize payload
  // ----------------------------------------------------------
  /**
   * Load points from the back-end.
   * Tolerates:
   *   - raw array:           [ {lat,lon,intensity,...}, ... ]
   *   - object-wrapped:      { points: [...], autoRefreshMs: 60000 }
   */
  async function loadPayload() {
    const res = await fetch(apiUrl(), { cache: "no-store" });
    if (!res.ok) {
      // A09: keep error lean; do not dump entire response body here.
      throw new Error(`Failed to load heat points: ${res.status}`);
    }
    const data = await res.json();

    if (Array.isArray(data)) {
      return { points: data, autoRefreshMs: 0 };
    }
    return {
      points: Array.isArray(data.points) ? data.points : [],
      autoRefreshMs: Number(data.autoRefreshMs || 0),
    };
  }

  // ----------------------------------------------------------
  // Heat tuple conversion
  // ----------------------------------------------------------
  /**
   * Convert {lat,lon,intensity} objects to [lat,lon,intensity] tuples that
   * leaflet-heat expects.
   */
  function toHeatTuples(points) {
    return points
      .filter(p => p && typeof p.lat === "number" && typeof p.lon === "number")
      .map(p => [p.lat, p.lon, Number(p.intensity || 0.6)]);
  }

  // ----------------------------------------------------------
  // Layer clearing
  // ----------------------------------------------------------
  /**
   * Remove prior heat and hover layers from the map to avoid memory leaks
   * or duplicate markers.
   */
  function clearLayers(map) {
    if (heatLayerRef) {
      try {
        map.removeLayer(heatLayerRef);
      } catch (e) {
        console.warn("Error removing heat layer:", e);
      }
      heatLayerRef = null;
    }
    hoverLayerRefs.forEach(m => {
      try {
        map.removeLayer(m);
      } catch (e) {
        console.warn("Error removing hover marker:", e);
      }
    });
    hoverLayerRefs = [];
  }

  // ----------------------------------------------------------
  // Heat layer rendering
  // ----------------------------------------------------------
  /**
   * Render the heat layer using leaflet-heat.
   */
  function renderHeat(map, heatTuples) {
    if (!Array.isArray(heatTuples) || heatTuples.length === 0) return;
    heatLayerRef = L.heatLayer(heatTuples, {
      radius: 25,
      blur: 20,
      minOpacity: 0.35,
    }).addTo(map);
  }

  // ----------------------------------------------------------
  // Hover markers for tooltips
  // ----------------------------------------------------------
  /**
   * Tiny invisible markers that show tooltips on hover.
   * Values are interpolated into plain text tooltips (no HTML) which
   * mitigates XSS even if backend fields contained unexpected characters.
   */
  function addHoverMarkers(map, points) {
    points.forEach(p => {
      if (typeof p.lat !== "number" || typeof p.lon !== "number") return;

      const m = L.circleMarker([p.lat, p.lon], {
        radius: 1,
        opacity: 0,
        fillOpacity: 0,
      });

      const pct = Math.round(Number(p.intensity || 0.6) * 100);
      const layer = p.layer ? String(p.layer) : (p.metric !== undefined ? "L7/L3" : "");
      const dir = p.direction ? String(p.direction) : "";
      const cc = p.country ? String(p.country) : "";

      const parts = [];
      if (cc)    parts.push(`Country: ${cc}`);
      if (layer) parts.push(`Layer: ${layer}`);
      if (dir)   parts.push(`Direction: ${dir}`);
      parts.push(`Heat: ${pct}%`);

      const label = parts.join(" • ");

      m.bindTooltip(label, { sticky: true });
      m.addTo(map);
      hoverLayerRefs.push(m);
    });
  }

  // ----------------------------------------------------------
  // Sidebar: top countries summary
  // ----------------------------------------------------------
  /**
   * Update the sidebar’s meta text and Top Countries list.
   *
   * OWASP A03/A05: Instead of using innerHTML with interpolated values from
   * the backend, build elements via DOM APIs and use textContent to avoid
   * client-side XSS if country codes or metrics were ever compromised.
   */
  function updateSidebar(points) {
    const metaEl = document.getElementById("tm-meta");
    const countriesEl = document.getElementById("tm-top-countries");

    if (!metaEl && !countriesEl) return;

    if (!points || !points.length) {
      if (metaEl) metaEl.textContent = "No live attack hotspots";
      if (countriesEl) countriesEl.innerHTML = "";
      return;
    }

    const totalPoints = points.length;
    const byCountry = {};
    let totalMetricAll = 0;

    points.forEach(p => {
      const country = (p.country || "??").toString().toUpperCase();
      const metric = Number(p.metric || 0) || 1; // fallback so counts still make sense
      totalMetricAll += metric;
      byCountry[country] = (byCountry[country] || 0) + metric;
    });

    // Top 10 countries by metric
    const topCountries = Object.entries(byCountry)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    if (countriesEl) {
      // Clear existing children safely
      countriesEl.innerHTML = "";

      topCountries.forEach(([code, val]) => {
        const pct = totalMetricAll ? (val / totalMetricAll) * 100 : 0;

        const li = document.createElement("li");
        li.className = "d-flex justify-content-between";

        const spanCode = document.createElement("span");
        spanCode.textContent = code; // textContent guards against XSS

        const spanPct = document.createElement("span");
        spanPct.className = "text-muted";
        spanPct.textContent = `${pct.toFixed(1)}%`;

        li.appendChild(spanCode);
        li.appendChild(spanPct);
        countriesEl.appendChild(li);
      });
    }

    if (metaEl) {
      metaEl.textContent = `${totalPoints} live attack hotspots`;
    }
  }

  // ----------------------------------------------------------
  // Legend rendering
  // ----------------------------------------------------------
  /**
   * Add a small legend showing intensity gradient.
   * Uses static innerHTML we fully control (no untrusted data interpolation).
   */
  function addLegend(map) {
    const legend = L.control({ position: "bottomright" });

    legend.onAdd = function () {
      const div = L.DomUtil.create("div", "tm-legend card p-2");
      div.style.background = "#0f141a";
      div.style.border = "1px solid #1f2a33";
      div.style.color = "#c7d0da";
      div.style.fontSize = "0.85rem";
      div.style.lineHeight = "1.3em";
      div.innerHTML = `
        <strong>Attack Intensity</strong><br>
        <canvas id="legend-gradient" width="120" height="10"
                style="display:block;margin:4px 0;border-radius:3px;"></canvas>
        <div style="display:flex;justify-content:space-between;font-size:0.75rem;">
          <span>Low</span><span>High</span>
        </div>
      `;
      return div;
    };

    legend.addTo(map);

    // Draw the gradient bar once the canvas is in the DOM
    setTimeout(() => {
      const canvas = document.getElementById("legend-gradient");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const grad = ctx.createLinearGradient(0, 0, 120, 0);
      grad.addColorStop(0,   "#0b1220");
      grad.addColorStop(0.25,"#1a2d4b");
      grad.addColorStop(0.5, "#243a61");
      grad.addColorStop(0.75,"#2f4a7a");
      grad.addColorStop(1,   "#4c67a8");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 120, 10);
    }, 0);
  }

  // ----------------------------------------------------------
  // Core refresh pipeline
  // ----------------------------------------------------------
  /**
   * Perform a full refresh: fetch -> clear -> render heat/markers + sidebar.
   * Returns: autoRefreshMs from the backend (or 0 if not provided).
   */
  async function refresh(map) {
    const payload = await loadPayload();
    const tuples = toHeatTuples(payload.points);

    clearLayers(map);
    renderHeat(map, tuples);
    addHoverMarkers(map, payload.points);
    updateSidebar(payload.points);

    return payload.autoRefreshMs || 0;
  }

  // ----------------------------------------------------------
  // Initialization
  // ----------------------------------------------------------
  document.addEventListener("DOMContentLoaded", async () => {
    const el = document.getElementById(elId);
    if (!el) return;

    // Base Leaflet map setup
    const map = L.map(elId, {
      worldCopyJump: true,
      attributionControl: false,
    }).setView([20, 0], 2);

    // Base tiles: OSM + dark basemap
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap",
    }).addTo(map);

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap & CARTO",
    }).addTo(map);

    addLegend(map);

    try {
      // Initial fetch + render
      let interval = await refresh(map);

      const defaultMs = 60_000; // fallback refresh, 60s
      const schedule = (ms) => {
        if (refreshTimer) clearInterval(refreshTimer);

        const intervalMs = ms > 0 ? ms : defaultMs;

        refreshTimer = setInterval(async () => {
          try {
            await refresh(map);
          } catch (e) {
            console.warn("ThreatMap auto-refresh failed:", e);
          }
        }, intervalMs);
      };

      schedule(interval);

      // Re-fetch when the source selector changes
      if (sourceSel) {
        sourceSel.addEventListener("change", async () => {
          try {
            const newMs = await refresh(map);
            schedule(newMs);
          } catch (e) {
            console.error("ThreatMap refresh on source change failed:", e);
            updateSidebar([]);
          }
        });
      }
    } catch (e) {
      console.error("ThreatMap failed to initialize:", e);
      updateSidebar([]);
    }
  });
})();
