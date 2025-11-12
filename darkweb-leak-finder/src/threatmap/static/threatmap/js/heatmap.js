// ------------------------------------------------------------
// ThreatMap front-end (Leaflet + heat layer)
// - Looks for a div with id="tm-world-map"
// - Fetches points from /threatmap/api/points/
// - Renders a heat layer and (optionally) auto-refreshes
// ------------------------------------------------------------
(function () {
  const elId = "tm-world-map";                 // must match your template div id
  const API  = window.THREATMAP_API || "/threatmap/api/points/"; // overrideable

  async function loadPoints() {
    const res = await fetch(API, { cache: "no-store" });
    if (!res.ok) throw new Error(`Failed to load heat points: ${res.status}`);
    return res.json();
  }

  function renderHeat(map, points) {
    if (!Array.isArray(points) || points.length === 0) return;
    // Remove existing heat layer(s) first
    map.eachLayer(l => {
      if (l instanceof L.HeatLayer) map.removeLayer(l);
    });
    L.heatLayer(points, { radius: 25, blur: 20, minOpacity: 0.35 }).addTo(map);
  }

    // After you compute `points`, also build markers just for tooltips
    function addHoverMarkers(map, points) {
      points.forEach(([lat, lon, intensity]) => {
        const m = L.circleMarker([lat, lon], { radius: 1, opacity: 0, fillOpacity: 0 });
        m.bindTooltip(`Intensity: ${(intensity * 100).toFixed(0)}%`, { sticky: true });
        m.addTo(map);
      });
    }

  document.addEventListener("DOMContentLoaded", async () => {
    const el = document.getElementById(elId);
    if (!el) return; // nothing to do if map container missing

    // Base map
    const map = L.map(elId, { worldCopyJump: true, attributionControl: false }).setView([20, 0], 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap"
    }).addTo(map);

    // Dark tile layer (better contrast on dark UI)
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap & CARTO"
    }).addTo(map);

    // Refined legend: shows color scale + label for clarity
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
        <canvas id="legend-gradient" width="120" height="10" style="display:block;margin:4px 0;border-radius:3px;"></canvas>
        <div style="display:flex;justify-content:space-between;font-size:0.75rem;">
          <span>Low</span><span>High</span>
        </div>
      `;
      return div;
    };

    legend.addTo(map);

    // Draw gradient on the canvas (matching your heat color ramp)
    const canvas = document.getElementById("legend-gradient");
    if (canvas) {
      const ctx = canvas.getContext("2d");
      const grad = ctx.createLinearGradient(0, 0, 120, 0);
      grad.addColorStop(0, "#0b1220");   // low
      grad.addColorStop(0.25, "#1a2d4b");
      grad.addColorStop(0.5, "#243a61");
      grad.addColorStop(0.75, "#2f4a7a");
      grad.addColorStop(1, "#4c67a8");   // high
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 120, 10);
    }

    // First render
    try {
      const data = await loadPoints();
      renderHeat(map, data.points);

      // Auto-refresh if enabled by backend config
      const interval = Number(data.autoRefreshMs || 0);
      if (interval > 0) {
        setInterval(async () => {
          try {
            const fresh = await loadPoints();
            renderHeat(map, fresh.points);
          } catch (e) {
            console.warn("ThreatMap auto-refresh failed:", e);
          }
        }, interval);
      }
    } catch (e) {
      console.error("ThreatMap failed to initialize:", e);
    }
  });
})();
