// ------------------------------------------------------------
// ThreatMap front-end (Leaflet + heat + source selector + sidebar)
// ------------------------------------------------------------
(function () {
  const elId = "tm-world-map";
  const API  = window.THREATMAP_API || "/threatmap/api/points/";
  const sourceSel = document.getElementById("tm-radar-source");

  let heatLayerRef = null;
  let hoverLayerRefs = [];
  let refreshTimer = null;

  // Build the API URL, including ?source=... if a dropdown is present/selected
  function apiUrl() {
    const url = new URL(API, window.location.origin);
    if (sourceSel && sourceSel.value) {
      url.searchParams.set("source", sourceSel.value);
    }
    return url.toString();
  }

  // Load points; tolerate either an array or an object {points, autoRefreshMs}
  async function loadPayload() {
    const res = await fetch(apiUrl(), { cache: "no-store" });
    if (!res.ok) {
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

  // Convert {lat,lon,intensity} objects to [lat,lon,intensity] tuples that leaflet-heat expects
  function toHeatTuples(points) {
    return points
      .filter(p => p && typeof p.lat === "number" && typeof p.lon === "number")
      .map(p => [p.lat, p.lon, Number(p.intensity || 0.6)]);
  }

  // Remove prior heat and hover layers
  function clearLayers(map) {
    if (heatLayerRef) {
      try { map.removeLayer(heatLayerRef); } catch (e) {}
      heatLayerRef = null;
    }
    hoverLayerRefs.forEach(m => {
      try { map.removeLayer(m); } catch (e) {}
    });
    hoverLayerRefs = [];
  }

  // Render the heat layer
  function renderHeat(map, heatTuples) {
    if (!Array.isArray(heatTuples) || heatTuples.length === 0) return;
    heatLayerRef = L.heatLayer(heatTuples, {
      radius: 25,
      blur: 20,
      minOpacity: 0.35,
    }).addTo(map);
  }

  // Tiny invisible markers to show tooltips on hover
  function addHoverMarkers(map, points) {
    points.forEach(p => {
      if (typeof p.lat !== "number" || typeof p.lon !== "number") return;
      const m = L.circleMarker([p.lat, p.lon], { radius: 1, opacity: 0, fillOpacity: 0 });
      const pct = Math.round(Number(p.intensity || 0.6) * 100);
      const layer = p.layer ? p.layer : (p.metric !== undefined ? "L7/L3" : "");
      const dir = p.direction ? p.direction : "";
      const cc = p.country ? p.country : "";
      const label = [
        cc && `Country: ${cc}`,
        layer && `Layer: ${layer}`,
        dir && `Direction: ${dir}`,
        `Heat: ${pct}%`,
      ].filter(Boolean).join(" • ");
      m.bindTooltip(label, { sticky: true });
      m.addTo(map);
      hoverLayerRefs.push(m);
    });
  }

  // Sidebar: show top 10 countries by percentage
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
      const country = (p.country || "??").toUpperCase();
      const metric = Number(p.metric || 0) || 1; // fallback so counts still make sense
      totalMetricAll += metric;
      byCountry[country] = (byCountry[country] || 0) + metric;
    });

    // Top 10 countries by metric
    const topCountries = Object.entries(byCountry)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    if (countriesEl) {
      countriesEl.innerHTML = topCountries.map(([code, val]) => {
        const pct = totalMetricAll ? (val / totalMetricAll) * 100 : 0;
        return `
          <li class="d-flex justify-content-between">
            <span>${code}</span>
            <span class="text-muted">${pct.toFixed(1)}%</span>
          </li>
        `;
      }).join("");
    }

    if (metaEl) {
      metaEl.textContent = `${totalPoints} live attack hotspots`;
    }
  }

  // Create the gradient legend
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

    setTimeout(() => {
      const canvas = document.getElementById("legend-gradient");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
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

  // Perform a full refresh: fetch -> clear -> render heat/markers + sidebar
  async function refresh(map) {
    const payload = await loadPayload();
    const tuples = toHeatTuples(payload.points);
    clearLayers(map);
    renderHeat(map, tuples);
    addHoverMarkers(map, payload.points);
    updateSidebar(payload.points);
    return payload.autoRefreshMs || 0;
  }

  document.addEventListener("DOMContentLoaded", async () => {
    const el = document.getElementById(elId);
    if (!el) return;

    const map = L.map(elId, {
      worldCopyJump: true,
      attributionControl: false,
    }).setView([20, 0], 2);

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap",
    }).addTo(map);

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap & CARTO",
    }).addTo(map);

    addLegend(map);

    try {
      let interval = await refresh(map);

      const defaultMs = 60_000;
      const schedule = (ms) => {
        if (refreshTimer) clearInterval(refreshTimer);
        refreshTimer = setInterval(async () => {
          try {
            await refresh(map);
          } catch (e) {
            console.warn("ThreatMap auto-refresh failed:", e);
          }
        }, ms > 0 ? ms : defaultMs);
      };
      schedule(interval);

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
