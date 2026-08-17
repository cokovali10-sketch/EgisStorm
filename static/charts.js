const Charts = (() => {
  const C = {
    good: "var(--good)",
    warn: "var(--warn)",
    bad: "var(--bad)",
    accent: "var(--accent)",
  };

  function donut(data, { size = 180, thickness = 26, centerLabel = "", centerSub = "", centerColor = "" } = {}) {
    const r = (size - thickness) / 2;
    const cx = size / 2, cy = size / 2;
    const total = data.reduce((s, d) => s + d.value, 0) || 1;
    let offset = 0, arcs = "";
    data.forEach((d) => {
      const angle = (d.value / total) * 360;
      const large = angle > 180 ? 1 : 0;
      const a0 = ((offset - 90) * Math.PI) / 180;
      const a1 = ((offset + angle - 90) * Math.PI) / 180;
      const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
      const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
      arcs += `<path d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}" fill="none" stroke="${d.color || C.accent}" stroke-width="${thickness}"/>`;
      offset += angle;
    });
    return `<svg class="donut" width="${size}" height="${size}">${arcs}
      <text x="${cx}" y="${cy - 4}" text-anchor="middle" class="donut-num" fill="${centerColor || "var(--text)"}">${centerLabel}</text>
      ${centerSub ? `<text x="${cx}" y="${cy + 18}" text-anchor="middle" class="donut-sub" fill="var(--muted)">${centerSub}</text>` : ""}
    </svg>`;
  }

  function bar(data, { height = 140, labels = true, w } = {}) {
    const max = Math.max(...data.map((d) => d.value), 1);
    const bw = 40;
    const width = w || Math.max(220, data.length * (bw + 16) + 20);
    let bars = "", lbl = "";
    data.forEach((d, i) => {
      const h = Math.max(2, (d.value / max) * height);
      const x = 20 + i * (bw + 16);
      const y = height - h;
      bars += `<rect x="${x}" y="${y}" width="${bw}" height="${h}" rx="5" fill="${d.color || C.accent}"><title>${d.label}: ${d.value}</title></rect>`;
      if (labels) lbl += `<text x="${x + bw / 2}" y="${height + 14}" text-anchor="middle" class="chart-lbl" fill="var(--muted)" font-size="11">${d.label}</text>`;
      if (d.sub && labels) lbl += `<text x="${x + bw / 2}" y="${height + 28}" text-anchor="middle" class="chart-lbl" fill="var(--muted)" font-size="10">${d.sub}</text>`;
    });
    return `<svg width="${width}" height="${height + (labels ? 34 : 0)}">${bars}${lbl}</svg>`;
  }

  function gauge(value, max = 100, color = C.good, { size = 170, label = "" } = {}) {
    const v = Math.min(max, Math.max(0, value));
    return donut([{ value: v, color }], {
      size,
      centerLabel: `${Math.round(v)}${max > 100 ? "" : "%"}`,
      centerSub: label,
    });
  }

  function rangeBar(startPct, endPct, { todayPct = null, label = "", w = 520, h = 40 } = {}) {
    const x0 = (startPct / 100) * w, x1 = (endPct / 100) * w;
    let mark = "";
    if (todayPct != null) {
      const mx = (todayPct / 100) * w;
      mark = `<line x1="${mx}" y1="2" x2="${mx}" y2="${h - 2}" stroke="var(--text)" stroke-width="2"/><text x="${mx}" y="${h + 12}" text-anchor="middle" font-size="11" fill="var(--text)">сегодня</text>`;
    }
    return `<svg width="${w}" height="${h + 16}">
      <rect x="0" y="4" width="${w}" height="${h - 8}" rx="6" fill="var(--line)"/>
      <rect x="${x0.toFixed(1)}" y="4" width="${(x1 - x0).toFixed(1)}" height="${h - 8}" rx="6" fill="var(--accent)"/>
      ${mark}
      <text x="0" y="${h + 30}" font-size="11" fill="var(--muted)">${label}</text>
    </svg>`;
  }

  function line(data, { w = 540, h = 170, color = C.accent } = {}) {
    const max = Math.max(...data.map((d) => d.y), 1);
    const pad = 26;
    const px = (i) => pad + (i * (w - 2 * pad)) / Math.max(1, data.length - 1);
    const py = (v) => h - pad - (v / max) * (h - 2 * pad);
    const pts = data.map((d, i) => `${px(i).toFixed(1)},${py(d.y).toFixed(1)}`).join(" ");
    const area = `M ${px(0)} ${h - pad} L ${pts.replace(/ /g, " L ")} L ${px(data.length - 1)} ${h - pad} Z`;
    let dots = "";
    data.forEach((d, i) => {
      dots += `<circle cx="${px(i)}" cy="${py(d.y)}" r="3.5" fill="${color}"><title>${d.label}: ${d.y}</title></circle>`;
      if (i % Math.ceil(data.length / 6) === 0)
        dots += `<text x="${px(i)}" y="${py(d.y) - 8}" text-anchor="middle" font-size="10" fill="var(--muted)">${d.label}</text>`;
    });
    return `<svg width="${w}" height="${h}">
      <path d="${area}" fill="${color}" opacity="0.15"/>
      <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2"/>
      ${dots}
    </svg>`;
  }

  return { donut, bar, gauge, rangeBar, line, C };
})();