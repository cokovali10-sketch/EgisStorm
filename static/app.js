const $ = (sel) => document.querySelector(sel);

const scoreState = { breaches: 0, passwordPwned: false };

document.querySelectorAll(".nav").forEach((nav) => {
    nav.addEventListener("click", () => {
        document.querySelectorAll(".nav").forEach((n) => n.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
        nav.classList.add("active");
        $("#tool-" + nav.dataset.tool).classList.add("active");
    });
});

async function post(url, body) {
    const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Request failed");
    return data;
}

function kv(entries) {
    return `<dl class="kv">${entries.map(([k, v]) => `<dt>${k}</dt><dd>${v ?? "—"}</dd>`).join("")}</dl>`;
}

function clsOf(label) {
    if (label === "сильный" || label === "good") return "good";
    if (label === "хороший") return "info";
    if (label === "средний" || label === "warn") return "warn";
    return "bad";
}

function copyText(text) {
    navigator.clipboard?.writeText(text).then(() => toast("Скопировано", "info"));
}

function attrEsc(s) {
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function toast(msg, type = "info") {
    const t = document.createElement("div");
    t.className = "toast " + type;
    t.textContent = msg;
    $("#toasts").appendChild(t);
    setTimeout(() => t.remove(), 2600);
}

function downloadJSON(name, obj) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name + ".json";
    a.click();
    URL.revokeObjectURL(a.href);
    toast("JSON скачан", "info");
}

const TOOL_LABELS = {
    email: "Email", password: "Пароль", dns: "DNS", whois: "WHOIS", ip: "IP",
    cert: "SSL", headers: "Headers", hash: "Хеш", jwt: "JWT", urlcheck: "URL",
    totp: "2FA", wg: "WireGuard", genpw: "Генератор", b64: "Base64",
    ipwhois: "IP WHOIS", subnet: "Subnet", expand: "Развёртка", mxcheck: "MX", cve: "CVE",
    myip: "Мой IP", portcheck: "Порт", robots: "robots", crypt: "AES",
};

function addHistory(tool, query, summary) {
    const arr = JSON.parse(localStorage.getItem("egis_history") || "[]");
    arr.unshift({ ts: Date.now(), tool, query, summary });
    if (arr.length > 20) arr.length = 20;
    localStorage.setItem("egis_history", JSON.stringify(arr));
    renderHistory();
}

function renderHistory() {
    const arr = JSON.parse(localStorage.getItem("egis_history") || "[]");
    $("#historyList").innerHTML = arr.map((h) => {
        const time = new Date(h.ts).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
        return `<li class="hist-item" onclick="goTool('${h.tool}')">
            <span class="hist-tool">${TOOL_LABELS[h.tool] || h.tool}</span>
            <span class="hist-q">${h.query}</span>
            <span class="hist-time">${time}</span>
            ${h.summary ? `<span class="hist-sum">${h.summary}</span>` : ""}
        </li>`;
    }).join("") || `<li class="hist-empty">Пока пусто</li>`;
}

function goTool(name) {
    document.querySelectorAll(".nav").forEach((n) => n.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    const nav = document.querySelector(`.nav[data-tool="${name}"]`);
    nav && nav.classList.add("active");
    $("#tool-" + name).classList.add("active");
}

$("#btnClearHistory").addEventListener("click", () => { localStorage.removeItem("egis_history"); renderHistory(); toast("История очищена"); });

function renderBreaches(result) {
    const box = $("#resultEmail");
    if (result.error) { box.innerHTML = `<div class="err">${result.error}</div>`; return; }
    if (!result.breaches.length) {
        box.innerHTML = `<div class="card"><h3 class="good">В утечках не найден</h3><p class="empty">Этот адрес не фигурирует в известных базах.</p></div>`;
        scoreState.breaches = 0;
        addHistory("email", result.email, "утечек нет");
        return;
    }
    scoreState.breaches = result.breaches.length;
    const modeNote = result.mode === "demo"
        ? `<p class="empty">Режим демо: задайте HIBP_API_KEY для живых данных.</p>`
        : "";

    const byYear = {};
    result.breaches.forEach((b) => {
        const y = String(b.BreachDate).slice(0, 4) || "?";
        byYear[y] = (byYear[y] || 0) + 1;
    });
    const years = Object.keys(byYear).sort();
    const chart = years.length
        ? `<div class="chart-block"><h3 class="section">Утечки по годам</h3>${Charts.bar(years.map((y) => ({ label: y, value: byYear[y], color: Charts.C.bad })), { height: 120 })}</div>`
        : "";

    box.innerHTML = modeNote + chart +
        result.breaches.map((b) => `
        <div class="card">
            <h3>${b.Title} <span class="pill">${Number(b.PwnCount).toLocaleString("ru")} аккаунтов</span></h3>
            <div class="meta">
                <span>📅 ${b.BreachDate}</span>
                <span>🌐 ${b.Domain || "—"}</span>
                <span class="${b.IsVerified ? "good" : "warn"}">${b.IsVerified ? "подтверждённая" : "неподтверждённая"}</span>
            </div>
            <p class="desc">${b.Description}</p>
            <div>${(b.DataClasses || []).map((d) => `<span class="pill">${d}</span>`).join("")}</div>
        </div>`).join("") +
        `<button type="button" class="ghost" onclick="downloadJSON('${attrEsc(result.email)}', ${attrEsc(JSON.stringify(result.breaches))})">Экспорт JSON</button>`;
    addHistory("email", result.email, `в ${result.breaches.length} утечках`);
}

function renderPassword(data) {
    const box = $("#resultPassword");
    const n = data.pwned_count;
    scoreState.passwordPwned = n > 0;
    const cls = n === 0 ? "good" : "bad";
    const msg = n === 0
        ? "Этот пароль не встречается в известных утечках."
        : `Опасно: пароль встречается в утечках ${Number(n).toLocaleString("ru")} раз.`;
    const s = data.strength;
    const gaugeColor = s.score === "сильный" ? Charts.C.good : s.score === "хороший" ? Charts.C.accent : s.score === "средний" ? Charts.C.warn : Charts.C.bad;
    const gaugeMax = Math.max(100, s.entropy * 1.3);
    box.innerHTML = `<div class="card">
        <div class="chart-flex">
            ${Charts.gauge(s.entropy, gaugeMax, gaugeColor, { label: "энтропия, бит" })}
            <div>
                <h3>В утечках: <span class="big-num ${cls}">${Number(n).toLocaleString("ru")}</span></h3>
                <p class="desc">${msg}</p>
                <div class="meta"><span>Длина: ${s.length}</span><span>Оценка: <span class="${clsOf(s.score)}">${s.score}</span></span></div>
                <p class="desc">${(data.tips || []).map((t) => `<span class="pill">${t}</span>`).join("")}</p>
            </div>
        </div>
    </div>`;
    addHistory("password", "••••" + s.length + " симв.", n > 0 ? `скомпрометирован (${n})` : "чист");
}

function updateScore() {
    const total = scoreState.breaches + (scoreState.passwordPwned ? 1 : 0);
    const factors = [];
    if (scoreState.breaches === 0) factors.push("Email чист");
    else factors.push(`Email в ${scoreState.breaches} утечке(ах)`);
    if (!scoreState.passwordPwned) factors.push("Пароль не скомпрометирован");
    else factors.push("Пароль скомпрометирован");

    const pct = Math.max(0, 100 - total * 35);
    const color = pct >= 70 ? "var(--good)" : pct >= 40 ? "var(--warn)" : "var(--bad)";
    const ring = $("#scoreRing");
    ring.style.background = `conic-gradient(${color} ${pct}%, var(--line) ${pct}%)`;
    ring.innerHTML = `<span>${pct}</span>`;
    $("#scoreTitleSmall").textContent = pct >= 70 ? "Низкий риск" : pct >= 40 ? "Средний риск" : "Высокий риск";
    $("#scoreMini").hidden = false;
    $("#scoreMini").title = factors.join("\n");
}

function renderDns(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    const present = Object.entries(d.records).filter(([, v]) => Array.isArray(v));
    const chart = Charts.bar(
        present.map(([rt, v]) => ({ label: rt, value: v.length, color: Charts.C.accent })),
        { height: 120 }
    );
    const sections = Object.entries(d.records).map(([rtype, values]) => {
        if (values === null) return `<div class="card"><h3>${rtype}</h3><p class="empty">не найден / ошибка разрешения</p></div>`;
        if (!values.length) return `<div class="card"><h3>${rtype}</h3><p class="empty">нет записей</p></div>`;
        return `<div class="card"><h3>${rtype} <span class="pill">${values.length}</span></h3>${values.map((v) => `<pre class="code">${v}</pre>`).join("")}</div>`;
    }).join("");
    addHistory("dns", d.host, `${present.reduce((s, [, v]) => s + v.length, 0)} записей`);
    return `<h3 class="section">Записи для ${d.host}</h3><div class="chart-block">${chart}</div>` + sections +
        `<button type="button" class="ghost" onclick="downloadJSON('${attrEsc(d.host)}-dns', ${attrEsc(JSON.stringify(d.records))})">Экспорт JSON</button>`;
}

function renderWhois(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("whois", d.target, d.registrar);
    return `<div class="card">${kv([
        ["Домен", d.target],
        ["Handle", d.handle],
        ["Регистратор", d.registrar],
        ["Создан", d.created],
        ["Обновлён", d.updated],
        ["Истекает", d.expires],
        ["Страна", d.country],
        ["Сеть", d.network],
        ["Статусы", (d.status || []).join(", ") || "—"],
        ["NS", (d.nameservers || []).join(", ") || "—"],
    ])}</div>
    <button type="button" class="ghost" onclick="downloadJSON('${attrEsc(d.target)}-whois', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

function renderIp(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("ip", d.ip, d.country);
    return `<div class="card">${kv([
        ["IP", d.ip],
        ["Тип", d.type],
        ["Страна", d.country],
        ["Регион", d.region],
        ["Город", d.city],
        ["Координаты", d.latitude != null ? `${d.latitude}, ${d.longitude}` : null],
        ["Организация", d.org],
        ["Провайдер", d.isp],
        ["ASN", d.asn],
        ["Timezone", d.timezone],
        ["Reverse DNS", d.reverse_dns],
    ])}</div>
    <button type="button" class="ghost" onclick="downloadJSON('${attrEsc(d.ip)}-info', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

function renderCert(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    const status = d.expired ? `<span class="bad">истёк</span>` : d.expires_soon ? `<span class="warn">истекает (${d.days_left} дн.)</span>` : `<span class="good">действует (${d.days_left} дн.)</span>`;

    const start = new Date(d.not_before.replace(" UTC", "Z")).getTime();
    const end = new Date(d.not_after.replace(" UTC", "Z")).getTime();
    const total = end - start;
    let range = "";
    if (total > 0) {
        const startPct = 0, endPct = 100;
        const todayPct = Math.min(100, Math.max(0, ((Date.now() - start) / total) * 100));
        range = `<div class="chart-block"><h3 class="section">Срок действия сертификата</h3>${Charts.rangeBar(startPct, endPct, { todayPct, label: `${d.not_before} — ${d.not_after}` })}</div>`;
    }

    addHistory("cert", d.host, `${d.days_left} дн. до истечения`);
    return `<div class="card">
        <h3>${d.host} — ${status}</h3>
        ${kv([
            ["Издатель (issuer)", d.issuer],
            ["Владелец (subject)", d.subject],
            ["Серийный номер", d.serial],
            ["Версия", d.version],
            ["Алгоритм подписи", d.signature_algorithm],
            ["Действует с", d.not_before],
            ["Действует до", d.not_after],
            ["TLS", d.tls_version],
            ["Шифр", d.cipher],
            ["SHA-256", d.sha256_fingerprint],
        ])}
        <h3 class="section">SAN (домены сертификата)</h3>
        ${(d.san || []).map((s) => `<span class="pill">${s}</span>`).join("") || '<p class="empty">нет</p>'}
    </div>${range}
    <button type="button" class="ghost" onclick="downloadJSON('${attrEsc(d.host)}-cert', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

function renderHeaders(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    const present = d.checks.filter((c) => c.present).length;
    const missing = d.checks.length - present;
    const donut = `<div class="chart-block">
        ${Charts.donut([
            { label: "есть", value: present, color: Charts.C.good },
            { label: "нет", value: missing, color: Charts.C.bad },
        ], { centerLabel: `${d.score}%`, centerSub: "защита" })}
    </div>`;
    addHistory("headers", d.final_url, `${present}/${d.checks.length} заголовков`);
    return `<div class="card">
        <div class="chart-flex">
            ${donut}
            <div class="meta">
                <span>URL: ${d.final_url}</span>
                <span>HTTP ${d.status}</span>
                <span>Server: ${d.server}</span>
                <span>Редиректов: ${d.redirects}</span>
            </div>
        </div>
    </div>` +
    d.checks.map((c) => `<div class="card">
        <h3>${c.header} <span class="pill ${c.present ? "good" : "bad"}">${c.present ? "есть" : "нет"}</span></h3>
        ${c.value ? `<pre class="code">${c.value}</pre>` : ""}
        <p class="desc">${c.advice}</p>
    </div>`).join("") +
    `<button type="button" class="ghost" onclick="downloadJSON('${attrEsc(d.final_url.replace(/[^a-z0-9]/gi, "_"))}-headers', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

function renderHash(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("hash", d.text.length > 20 ? d.text.slice(0, 20) + "…" : d.text, d.identify.guess || "не определено");
    return Object.entries(d.hashes).map(([alg, h]) => `
        <div class="card"><h3>${alg}</h3><pre class="code">${h}</pre></div>`).join("") +
        `<div class="card"><h3>Определение</h3><p class="desc">${d.identify.guess ? `<span class="info">${d.identify.guess}</span>` : '<span class="warn">не определено</span>'} — ${d.identify.note}</p></div>`;
}

function renderJwt(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    const findings = (d.findings || []).map((f) => `<p class="desc ${f.severity === "bad" ? "bad" : f.severity === "warn" ? "warn" : "info"}">${f.text}</p>`).join("");
    addHistory("jwt", d.header.alg, d.payload.sub || "—");
    return `
        <div class="card"><h3>Header</h3><pre class="code">${JSON.stringify(d.header, null, 2)}</pre></div>
        <div class="card"><h3>Payload</h3><pre class="code">${JSON.stringify(d.payload, null, 2)}</pre></div>
        <div class="card"><h3>Signature</h3><pre class="code">${d.signature}</pre>${findings}</div>
        <button type="button" class="ghost" onclick="downloadJSON('jwt', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

function renderUrl(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    const counts = { good: 0, warn: 0, bad: 0 };
    d.flags.forEach((f) => counts[f.severity]++);
    const donut = counts.good + counts.warn + counts.bad
        ? `<div class="chart-block">${Charts.donut([
            { label: "безопасно", value: counts.good, color: Charts.C.good },
            { label: "риск", value: counts.warn, color: Charts.C.warn },
            { label: "опасно", value: counts.bad, color: Charts.C.bad },
        ].filter((x) => x.value > 0), { centerLabel: counts.bad ? "риск" : counts.warn ? "внимание" : "ок", centerSub: `${counts.bad} опасных` })}</div>`
        : "";
    addHistory("urlcheck", d.host, counts.bad ? `${counts.bad} опасных индикаторов` : "чисто");
    return `<div class="card">
        ${kv([
            ["URL", d.url],
            ["Схема", d.scheme],
            ["Хост", d.host],
            ["Путь", d.path || "/"],
        ])}
    </div>${donut}` +
    d.flags.map((f) => `<div class="card"><h3 class="${f.severity === "good" ? "good" : f.severity === "warn" ? "warn" : "bad"}">${f.severity === "good" ? "✓" : f.severity === "warn" ? "⚠" : "✗"} ${f.text}</h3></div>`).join("");
}

async function runForm(formSel, api, resultSel, renderer) {
    const form = $(formSel);
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const res = $(resultSel);
        res.innerHTML = `<p class="empty">Выполняем…</p>`;
        const body = {};
        form.querySelectorAll("input[name]").forEach((inp) => (body[inp.name] = inp.value));
        try { res.innerHTML = renderer(await post(api, body)); } catch (err) { res.innerHTML = `<div class="err">${err.message}</div>`; }
    });
}

runForm("#formEmail", "/api/email", "#resultEmail", (d) => { renderBreaches(d); updateScore(); return ""; });
runForm("#formPassword", "/api/password", "#resultPassword", (d) => { renderPassword(d); updateScore(); return ""; });
runForm("#formDns", "/api/dns", "#resultDns", renderDns);
runForm("#formWhois", "/api/whois", "#resultWhois", renderWhois);
runForm("#formIp", "/api/ip", "#resultIp", renderIp);
runForm("#formCert", "/api/cert", "#resultCert", renderCert);
runForm("#formHeaders", "/api/headers", "#resultHeaders", renderHeaders);
runForm("#formHash", "/api/hash", "#resultHash", renderHash);
runForm("#formJwt", "/api/jwt", "#resultJwt", renderJwt);
runForm("#formUrl", "/api/urlcheck", "#resultUrl", renderUrl);
runForm("#formWg", "/api/wireguard", "#resultWg", (d) => {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("wg", d.client_public.slice(0, 12) + "…", "конфиг создан");
    return `<div class="card">
        <h3>Ваш приватный ключ (сохраните!)</h3><pre class="code">${d.client_private}</pre>
        <h3>Публичный ключ клиента (добавьте на сервер)</h3><pre class="code">${d.client_public}</pre>
        <h3>Конфиг</h3><pre class="code">${d.config}</pre>
        <button type="button" onclick="copyText(${attrEsc(JSON.stringify(d.config))})">Копировать конфиг</button>
        <button type="button" class="ghost" onclick="downloadJSON('wg-config', ${attrEsc(JSON.stringify(d.config))})">Скачать .conf</button>
    </div>`;
});

runForm("#formIpwhois", "/api/ipwhois", "#resultIpwhois", renderIpWhois);
runForm("#formSubnet", "/api/subnet", "#resultSubnet", renderSubnet);
runForm("#formMx", "/api/mxcheck", "#resultMx", renderMx);
runForm("#formExpand", "/api/expand", "#resultExpand", renderExpand);
runForm("#formCve", "/api/cve", "#resultCve", renderCve);
runForm("#formPort", "/api/portcheck", "#resultPort", renderPort);
runForm("#formRobots", "/api/robots", "#resultRobots", renderRobots);

function renderPort(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    if (d.results) {
        const open = d.results.filter((r) => r.open);
        const chart = Charts.donut([
            { label: "открыто", value: open.length, color: Charts.C.bad },
            { label: "закрыто", value: d.results.length - open.length, color: Charts.C.good },
        ], { size: 150, centerLabel: `${open.length}/${d.results.length}`, centerSub: "открыто" });
        const rows = d.results.map((r) => `<div class="card"><h3>${r.port} ${r.service} <span class="pill ${r.open ? "bad" : "good"}">${r.open ? "открыт" : "закрыт"}</span></h3></div>`).join("");
        addHistory("portcheck", d.host, `${open.length} портов открыто`);
        return `<div class="chart-flex"><div class="chart-block">${chart}</div></div>${rows}`;
    }
    addHistory("portcheck", `${d.host}:${d.port}`, d.open ? "открыт" : "закрыт");
    return `<div class="card"><h3>${d.host}:${d.port} — <span class="${d.open ? "bad" : "good"}">${d.open ? "открыт" : "закрыт / недоступен"}</span></h3>${d.reason ? `<p class="small">${d.reason}</p>` : ""}</div>`;
}

function renderRobots(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("robots", d.base, d.status === 200 ? "файл есть" : "нет robots.txt");
    if (d.status !== 200) return `<div class="card"><p class="empty">На ${d.base} нет robots.txt (HTTP ${d.status}).</p></div>`;
    const groups = (d.groups || []).map((g) => `<div class="card">
        <h3>User-agent: <code>${g.agent}</code></h3>
        ${g.disallow.map((x) => `<p class="desc warn">✗ Disallow: ${x}</p>`).join("") || ""}
        ${g.allow.map((x) => `<p class="desc good">✓ Allow: ${x}</p>`).join("") || ""}
        ${!g.disallow.length && !g.allow.length ? '<p class="empty">правил нет</p>' : ""}
    </div>`).join("");
    return `<div class="card"><div class="meta"><span>${d.base}</span><span>HTTP ${d.status}</span><span>sitemap: ${d.sitemaps.length || "нет"}</span></div></div>${groups}
    ${d.sitemaps.map((s) => `<pre class="code">🗺 ${s}</pre>`).join("")}
    <button type="button" class="ghost" onclick="downloadJSON('robots', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

$("#btnMyIp").addEventListener("click", async () => {
    $("#resultMyIp").innerHTML = `<p class="empty">Определяем…</p>`;
    try {
        const d = await post("/api/myip", {});
        addHistory("myip", d.ip, d.country || "");
        $("#resultMyIp").innerHTML = `<div class="card">${kv([
            ["Адрес", d.ip],
            ["Страна", d.country],
            ["Город", d.city],
            ["Провайдер", d.isp],
            ["Организация", d.org],
            ["ASN", d.asn],
            ["Reverse DNS", d.reverse_dns],
        ])}</div>`;
    } catch (err) { $("#resultMyIp").innerHTML = `<div class="err">${err.message}</div>`; }
});

$("#btnCommonPorts").addEventListener("click", async () => {
    const host = $("#formPort input[name=host]").value;
    if (!host) { toast("Введите хост", "bad"); return; }
    $("#resultPort").innerHTML = `<p class="empty">Сканируем общие порты…</p>`;
    try {
        $("#resultPort").innerHTML = renderPort(await post("/api/portcheck", { host, common: true }));
    } catch (err) { $("#resultPort").innerHTML = `<div class="err">${err.message}</div>`; }
});

$("#btnCryptEnc").addEventListener("click", () => cryptCall("encrypt"));
$("#btnCryptDec").addEventListener("click", () => cryptCall("decrypt"));

async function cryptCall(mode) {
    const text = $("#cryptText").value;
    const passphrase = $("#cryptKey").value;
    if (!text || !passphrase) { toast("Заполните оба поля", "bad"); return; }
    $("#resultCrypt").innerHTML = `<p class="empty">…</p>`;
    try {
        const d = await post("/api/crypt", { text, passphrase, mode });
        addHistory("crypt", mode === "encrypt" ? "шифрование" : "расшифровка", d.result.length + " симв.");
        $("#resultCrypt").innerHTML = `<div class="card">
            <h3>${mode === "encrypt" ? "Зашифровано (Base64)" : "Расшифровано"}</h3>
            <pre class="code">${d.result}</pre>
            <p class="small">${d.algo}</p>
            <button type="button" onclick="copyText('${attrEsc(d.result)}')">Копировать</button>
        </div>`;
    } catch (err) { $("#resultCrypt").innerHTML = `<div class="err">${err.message}</div>`; }
}

function renderIpWhois(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("ipwhois", d.target, d.registrar || d.network);
    return `<div class="card">${kv([
        ["IP", d.target],
        ["Handle", d.handle],
        ["Владелец", d.registrar],
        ["Сеть", d.network],
        ["IPv", d.ip_version],
        ["Страна", d.country],
        ["Создан", d.created],
        ["Обновлён", d.updated],
        ["Истекает", d.expires],
        ["Статусы", (d.status || []).join(", ") || "—"],
    ])}</div>
    <button type="button" class="ghost" onclick="downloadJSON('${attrEsc(d.target)}-owner', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

function renderSubnet(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("subnet", d.cidr, `${d.usable_hosts} хост.`);
    const maskPct = (d.prefix / (d.version === "IPv4" ? 32 : 128)) * 100;
    const chart = Charts.rangeBar(0, 100, { todayPct: maskPct, label: `префикс /${d.prefix}` });
    return `<div class="chart-block">${chart}</div>
    <div class="card">${kv([
        ["Сеть", d.cidr],
        ["Версия", d.version],
        ["Сетевой адрес", d.network],
        ["Маска", d.netmask],
        ["Broadcast", d.broadcast],
        ["Всего адресов", d.total_addresses],
        ["Используемые хосты", d.usable_hosts],
        ["Первый хост", d.first_usable],
        ["Последний хост", d.last_usable],
        ["Класс", d.classful],
    ])}</div>`;
}

function renderMx(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("mxcheck", d.email, d.disposable ? "одноразовый домен" : (d.has_mx ? "MX есть" : "MX нет"));
    return `<div class="card">
        <h3>${d.email} <span class="pill ${d.disposable ? "bad" : d.has_mx ? "good" : "warn"}">${d.disposable ? "одноразовый" : d.has_mx ? "валидный домен" : "без MX"}</span></h3>
        ${kv([
            ["Домен", d.domain],
            ["MX записи", (d.mx || []).map((m) => `<pre class="code" style="margin:4px 0">${m}</pre>`).join("") || "—"],
            ["A запись", d.has_a ? '<span class="good">есть</span>' : '<span class="warn">нет</span>'],
            ["Одноразовый", d.disposable ? '<span class="bad">да</span>' : '<span class="good">нет</span>'],
        ])}
    </div>`;
}

function renderExpand(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    const chain = (d.chain || []).map((c, i) => `
        <div class="card">
            <div class="meta"><span>Шаг ${i + 1}</span><span class="pill ${c.status >= 400 ? "bad" : "info"}">HTTP ${c.status}</span></div>
            <pre class="code">${c.url}</pre>
            ${c.location ? `<p class="desc">→ ${c.location}</p>` : ""}
        </div>`).join("");
    addHistory("expand", d.start.slice(0, 30), `${d.hops} редиректов`);
    return `<div class="card"><h3 class="${d.hops ? "warn" : "good"}">${d.hops ? `⚠ ${d.hops} редиректов` : "✓ без редиректов"}</h3>
        <p class="empty">Конечный URL:</p><pre class="code">${d.final}</pre></div>${chain}
        <button type="button" class="ghost" onclick="downloadJSON('expand', ${attrEsc(JSON.stringify(d))})">Экспорт JSON</button>`;
}

function renderCve(d) {
    if (d.error) return `<div class="err">${d.error}</div>`;
    addHistory("cve", d.query, `${d.count} CVE`);
    if (!d.results.length) return `<div class="card"><p class="empty">Ничего не найдено по запросу «${d.query}».</p></div>`;
    return `<div class="card"><h3>Найдено: <span class="big-num">${d.count}</span></h3></div>` +
    d.results.map((c) => `
        <div class="card">
            <h3>${c.id} <span class="pill ${c.cvss >= 7 ? "bad" : c.cvss >= 4 ? "warn" : "good"}">CVSS ${c.cvss ?? "—"}</span></h3>
            <div class="meta"><span>📅 ${c.published}</span></div>
            <p class="desc">${c.summary}</p>
            ${(c.refs || []).length ? `<p class="small">${c.refs.map((r) => `<a class="small" href="${attrEsc(r)}" target="_blank" rel="noopener">${attrEsc(r.slice(0, 50))}</a>`).join(" · ")}</p>` : ""}
        </div>`).join("");
}

$("#btnGenPw").addEventListener("click", async () => {
    $("#resultGenPw").innerHTML = `<p class="empty">Генерируем…</p>`;
    try {
        const d = await post("/api/generate-password", {
            length: +$("#pwLength").value,
            numbers: $("#pwNumbers").checked,
            symbols: $("#pwSymbols").checked,
            upper: $("#pwUpper").checked,
        });
        const gColor = d.score === "сильный" ? Charts.C.good : d.score === "хороший" ? Charts.C.accent : d.score === "средний" ? Charts.C.warn : Charts.C.bad;
        $("#resultGenPw").innerHTML = `
            <div class="card">
                <div class="chart-flex">
                    ${Charts.gauge(d.entropy, Math.max(100, d.entropy * 1.3), gColor, { label: "энтропия, бит" })}
                    <div style="flex:1">
                        <h3>Пароль</h3>
                        <pre class="code">${d.password}</pre>
                        <div class="meta"><span>Длина: ${d.length}</span><span>Оценка: <span class="${clsOf(d.score)}">${d.score}</span></span></div>
                        <button type="button" onclick="copyText('${attrEsc(d.password)}')">Копировать</button>
                    </div>
                </div>
            </div>`;
        addHistory("genpw", `${d.length} симв.`, d.score);
    } catch (err) { $("#resultGenPw").innerHTML = `<div class="err">${err.message}</div>`; }
});

$("#btnTotp").addEventListener("click", async () => {
    $("#resultTotp").innerHTML = `<p class="empty">Генерируем…</p>`;
    try {
        const d = await post("/api/totp", {});
        addHistory("totp", d.secret.slice(0, 8) + "…", "секрет создан");
        $("#resultTotp").innerHTML = `
            <div class="card totp">
                <img src="${d.qr_png}" alt="QR" width="180" height="180">
                <div>
                    <p>Секрет: <code class="code">${d.secret}</code> <button type="button" onclick="copyText('${attrEsc(d.secret)}')">Копировать</button></p>
                    <p>Текущий код: <span class="big-num good" id="totpNow">${d.current_code}</span></p>
                    <div class="totp-bar"><div class="totp-fill" id="totpFill"></div></div>
                    <p class="empty small">${d.uri}</p>
                </div>
            </div>`;
        startTotpCountdown(d.secret);
    } catch (err) { $("#resultTotp").innerHTML = `<div class="err">${err.message}</div>`; }
});

let totpTimer = null;

function startTotpCountdown(secret) {
    if (totpTimer) clearInterval(totpTimer);
    const tick = async () => {
        const now = new Date();
        const { code } = await Totp.code(secret, now);
        const el = $("#totpNow");
        if (el) el.textContent = code;
        const fill = $("#totpFill");
        if (fill) {
            const remain = 30 - (Math.floor(now.getTime() / 1000) % 30);
            fill.style.width = (remain / 30) * 100 + "%";
        }
    };
    tick();
    totpTimer = setInterval(tick, 1000);
}

$("#btnB64Enc").addEventListener("click", () => b64Call("encode"));
$("#btnB64Dec").addEventListener("click", () => b64Call("decode"));

async function b64Call(mode) {
    const text = $("#b64Text").value;
    if (!text) return;
    $("#resultB64").innerHTML = `<p class="empty">…</p>`;
    try {
        const d = await post("/api/b64", { text, mode });
        addHistory("b64", mode, `${d.result.length} симв.`);
        $("#resultB64").innerHTML = `<div class="card"><h3>${mode === "encode" ? "Base64" : "Декодировано"}</h3><pre class="code">${d.result}</pre><button type="button" onclick="copyText('${attrEsc(d.result)}')">Копировать</button></div>`;
    } catch (err) { $("#resultB64").innerHTML = `<div class="err">${err.message}</div>`; }
}

renderHistory();