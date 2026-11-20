(() => {
	"use strict";

	const MAX_RECORDS = 500;
	const MAX_ROWS = 160;
	const MINUTE_WINDOW = 30;
	const REDACTED_PATTERN = /\[REDACTED_[A-Z0-9_]+\]/g;
	const records = [];
	const counters = { clean: 0, alerts: 0 };
	const minuteBuckets = new Map();
	const elements = {
		status: document.getElementById("streamStatus"),
		statusText: document.getElementById("streamStatusText"),
		modeSelect: document.getElementById("modeSelect"),
		activeMode: document.getElementById("activeMode"),
		requestsPerMinute: document.getElementById("requestsPerMinute"),
		cleanCount: document.getElementById("cleanCount"),
		alertCount: document.getElementById("alertCount"),
		eventTotal: document.getElementById("eventTotal"),
		eventRows: document.getElementById("eventRows"),
		visibleRange: document.getElementById("visibleRange"),
		search: document.getElementById("eventSearch"),
		riskFilter: document.getElementById("riskFilter"),
		currentTime: document.getElementById("currentTime"),
		dialog: document.getElementById("eventDialog"),
		detailTitle: document.getElementById("detailTitle"),
		detailMeta: document.getElementById("detailMeta"),
		detailRisk: document.getElementById("detailRisk"),
		detailJson: document.getElementById("detailJson"),
		detailTruncated: document.getElementById("detailTruncated"),
		detailFindings: document.getElementById("detailFindings"),
		toast: document.getElementById("toast"),
		chartFallback: document.getElementById("chartFallback"),
		chartCanvas: document.getElementById("trafficChart")
	};

	let chart = null;
	let eventSource = null;
	let toastTimer = 0;

	function riskLevel(event) {
		const level = String(event.risk_level || "UNKNOWN").toUpperCase();
		if (["HIGH", "MEDIUM", "LOW"].includes(level)) return level;
		return event.findings?.length ? "HIGH" : "LOW";
	}

	function actionFor(event) {
		const status = String(event.status || "").toLowerCase();
		if (status === "blocked") return { label: "Bloqueada", className: "action-blocked" };
		if (status === "sanitized") return { label: "Sanitizada", className: "action-sanitized" };
		if (status === "engine_unavailable") return { label: "Motor no disponible", className: "action-fail" };
		if (status === "fail_open") return { label: "Paso abierto", className: "action-fail" };
		return { label: "Permitida", className: "action-passed" };
	}

	function formatTime(value) {
		const date = new Date(value);
		if (Number.isNaN(date.getTime())) return "--:--:--";
		return new Intl.DateTimeFormat("es-MX", {
			hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
		}).format(date);
	}

	function updateClock() {
		elements.currentTime.textContent = new Intl.DateTimeFormat("es-MX", {
			hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
		}).format(new Date());
	}

	function showToast(message, isError = false) {
		elements.toast.textContent = message;
		elements.toast.classList.toggle("error", isError);
		elements.toast.classList.add("visible");
		window.clearTimeout(toastTimer);
		toastTimer = window.setTimeout(() => elements.toast.classList.remove("visible"), 3200);
	}

	function setStreamState(state, label) {
		elements.status.dataset.state = state;
		elements.statusText.textContent = label;
	}

	function initChart() {
		if (typeof window.Chart !== "function") {
			elements.chartCanvas.hidden = true;
			elements.chartFallback.hidden = false;
			return;
		}
		const labels = Array.from({ length: MINUTE_WINDOW }, (_, index) => {
			const time = new Date(Date.now() - (MINUTE_WINDOW - index - 1) * 60_000);
			return time.toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit", hour12: false });
		});
		chart = new Chart(elements.chartCanvas, {
			type: "line",
			data: {
				labels,
				datasets: [
					{ label: "Limpias", data: Array(MINUTE_WINDOW).fill(0), borderColor: "#65d997", backgroundColor: "rgba(101,217,151,.08)", pointBackgroundColor: "#a6f2c5", pointRadius: 2, pointHoverRadius: 4, borderWidth: 2, tension: .32, fill: true },
					{ label: "Alertas", data: Array(MINUTE_WINDOW).fill(0), borderColor: "#ff8478", backgroundColor: "rgba(255,132,120,.04)", pointBackgroundColor: "#ff8478", pointRadius: 2, pointHoverRadius: 4, borderWidth: 1.5, tension: .32, fill: false }
				]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				animation: { duration: 280 },
				interaction: { intersect: false, mode: "index" },
				plugins: {
					legend: { display: false },
					tooltip: { backgroundColor: "#202b26", borderColor: "#35443c", borderWidth: 1, titleColor: "#e7eee9", bodyColor: "#aebbb2", padding: 10, displayColors: true }
				},
				scales: {
					x: { grid: { display: false }, border: { display: false }, ticks: { color: "#68776e", maxTicksLimit: 8, maxRotation: 0, font: { family: "DM Mono", size: 9 } } },
					y: { beginAtZero: true, border: { display: false }, grid: { color: "rgba(130,144,135,.11)" }, ticks: { color: "#68776e", precision: 0, maxTicksLimit: 5, padding: 8, font: { family: "DM Mono", size: 9 } } }
				}
			}
		});
	}

	function addToChart(event) {
		const timestamp = new Date(event.timestamp || Date.now()).getTime();
		const minute = Math.floor(timestamp / 60_000) * 60_000;
		const isAlert = ["blocked", "sanitized", "engine_unavailable"].includes(String(event.status).toLowerCase())
			|| riskLevel(event) === "HIGH"
			|| Boolean(event.findings?.length);
		const bucket = minuteBuckets.get(minute) || { clean: 0, alerts: 0 };
		bucket[isAlert ? "alerts" : "clean"] += 1;
		minuteBuckets.set(minute, bucket);

		const oldest = Math.floor(Date.now() / 60_000) * 60_000 - (MINUTE_WINDOW - 1) * 60_000;
		for (const key of minuteBuckets.keys()) if (key < oldest) minuteBuckets.delete(key);
		if (isAlert) counters.alerts += 1;
		else counters.clean += 1;
		updateMetrics();

		if (chart) {
			const nowMinute = Math.floor(Date.now() / 60_000) * 60_000;
			const visibleMinutes = Array.from({ length: MINUTE_WINDOW }, (_, index) => nowMinute - (MINUTE_WINDOW - index - 1) * 60_000);
			chart.data.labels = visibleMinutes.map(time => new Date(time).toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit", hour12: false }));
			chart.data.datasets[0].data = visibleMinutes.map(time => minuteBuckets.get(time)?.clean || 0);
			chart.data.datasets[1].data = visibleMinutes.map(time => minuteBuckets.get(time)?.alerts || 0);
			chart.update("none");
		}
	}

	function updateMetrics() {
		const currentMinute = Math.floor(Date.now() / 60_000) * 60_000;
		const currentBucket = minuteBuckets.get(currentMinute) || { clean: 0, alerts: 0 };
		elements.requestsPerMinute.textContent = String(currentBucket.clean + currentBucket.alerts);
		elements.cleanCount.textContent = counters.clean.toLocaleString("es-MX");
		elements.alertCount.textContent = counters.alerts.toLocaleString("es-MX");
	}

	function makeCell(className, text) {
		const cell = document.createElement("td");
		cell.className = className;
		cell.textContent = text;
		return cell;
	}

	function renderRows() {
		const query = elements.search.value.trim().toLowerCase();
		const filter = elements.riskFilter.value;
		const visible = records.filter(event => {
			const matchesQuery = !query || `${event.host || ""} ${event.category || ""}`.toLowerCase().includes(query);
			return matchesQuery && (filter === "ALL" || riskLevel(event) === filter);
		}).slice(0, MAX_ROWS);

		elements.eventRows.replaceChildren();
		if (!visible.length) {
			const row = document.createElement("tr");
			row.className = "empty-row";
			const cell = document.createElement("td");
			cell.colSpan = 6;
			cell.textContent = records.length ? "No hay eventos que coincidan" : "Esperando eventos de inspección";
			row.append(cell);
			elements.eventRows.append(row);
		} else {
			const fragment = document.createDocumentFragment();
			visible.forEach(event => {
				const row = document.createElement("tr");
				row.className = "event-row";
				row.tabIndex = 0;
				row.setAttribute("role", "button");
				row.setAttribute("aria-label", `Ver detalle de ${event.category || "evento"} en ${event.host || "host desconocido"}`);
				row.addEventListener("click", () => openDetails(event));
				row.addEventListener("keydown", keyboardEvent => {
					if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
						keyboardEvent.preventDefault();
						openDetails(event);
					}
				});

				row.append(makeCell("time-cell", formatTime(event.timestamp)));
				row.append(makeCell("category-cell", event.category || "UNKNOWN"));
				const host = makeCell("host-cell", event.host || "—");
				row.append(host);
				const riskCell = document.createElement("td");
				const badge = document.createElement("span");
				const risk = riskLevel(event);
				badge.className = `risk-badge risk-${risk.toLowerCase()}`;
				badge.textContent = risk === "UNKNOWN" ? "SIN DATO" : risk;
				riskCell.append(badge);
				row.append(riskCell);
				const actionCell = document.createElement("td");
				actionCell.className = "action-cell";
				const action = actionFor(event);
				const actionLabel = document.createElement("span");
				actionLabel.className = `action-label ${action.className}`;
				actionLabel.textContent = action.label;
				actionCell.append(actionLabel);
				row.append(actionCell);
				row.append(makeCell("row-arrow", "›"));
				fragment.append(row);
			});
			elements.eventRows.append(fragment);
		}

		elements.eventTotal.textContent = String(records.length);
		elements.visibleRange.textContent = `${visible.length} visibles · ${records.length} en memoria`;
	}

	function appendHighlightedText(container, text) {
		let cursor = 0;
		for (const match of text.matchAll(REDACTED_PATTERN)) {
			const start = match.index;
			if (start > cursor) container.append(document.createTextNode(text.slice(cursor, start)));
			const token = document.createElement("span");
			token.className = "redacted-token";
			token.textContent = match[0];
			container.append(token);
			cursor = start + match[0].length;
		}
		if (cursor < text.length) container.append(document.createTextNode(text.slice(cursor)));
	}

	function openDetails(event) {
		const time = formatTime(event.timestamp);
		elements.detailTitle.textContent = event.category || "Evento inspeccionado";
		elements.detailMeta.textContent = `${time}  /  ${event.method || "—"}  /  ${event.host || "host desconocido"}`;
		const risk = riskLevel(event);
		elements.detailRisk.className = `risk-badge risk-${risk.toLowerCase()}`;
		elements.detailRisk.textContent = risk;
		elements.detailTruncated.hidden = !event.body_truncated;

		let formattedBody;
		try {
			formattedBody = JSON.stringify(JSON.parse(event.sanitized_body || "null"), null, 2);
			if (formattedBody === "null" && !event.sanitized_body) formattedBody = "Sin cuerpo disponible";
		} catch {
			formattedBody = event.sanitized_body || "Sin cuerpo disponible";
		}
		elements.detailJson.replaceChildren();
		appendHighlightedText(elements.detailJson, formattedBody);

		elements.detailFindings.replaceChildren();
		(event.findings || []).forEach(finding => {
			const chip = document.createElement("span");
			chip.className = "finding-chip";
			chip.textContent = `${finding.kind}${finding.path ? ` · ${finding.path}` : ""}`;
			elements.detailFindings.append(chip);
		});
		elements.dialog.showModal();
	}

	async function loadMode() {
		try {
			const response = await fetch("/api/mode", { headers: { Accept: "application/json" } });
			if (!response.ok) throw new Error("No se pudo consultar el modo");
			const payload = await response.json();
			if (["MONITOR", "SANITIZE", "BLOCK"].includes(payload.mode)) {
				elements.modeSelect.value = payload.mode;
				elements.activeMode.textContent = payload.mode;
			}
		} catch (error) {
			showToast(error.message, true);
		}
	}

	async function changeMode(mode) {
		elements.modeSelect.disabled = true;
		try {
			const response = await fetch("/api/mode", {
				method: "POST",
				headers: { "Content-Type": "application/json", Accept: "application/json" },
				body: JSON.stringify({ mode })
			});
			const payload = await response.json();
			if (!response.ok) throw new Error(payload.error || "No se pudo cambiar el modo");
			elements.activeMode.textContent = payload.mode;
			showToast(`Modo actualizado: ${payload.mode}`);
		} catch (error) {
			elements.modeSelect.value = elements.activeMode.textContent;
			showToast(error.message, true);
		} finally {
			elements.modeSelect.disabled = false;
		}
	}

	function connectEvents() {
		if (eventSource) eventSource.close();
		eventSource = new EventSource("/events");
		eventSource.onopen = () => setStreamState("connected", "Stream activo");
		eventSource.onmessage = message => {
			try {
				const event = JSON.parse(message.data);
				records.unshift(event);
				if (records.length > MAX_RECORDS) records.length = MAX_RECORDS;
				addToChart(event);
				renderRows();
			} catch {
				showToast("Se recibió un evento con formato inválido", true);
			}
		};
		eventSource.onerror = () => setStreamState("disconnected", "Reconectando");
	}

	elements.modeSelect.addEventListener("change", () => changeMode(elements.modeSelect.value));
	elements.search.addEventListener("input", renderRows);
	elements.riskFilter.addEventListener("change", renderRows);
	document.addEventListener("keydown", event => {
		if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) {
			event.preventDefault();
			elements.search.focus();
		}
		if (event.key === "Escape" && elements.dialog.open) elements.dialog.close();
	});

	initChart();
	updateClock();
	window.setInterval(updateClock, 1000);
	window.setInterval(updateMetrics, 1000);
	loadMode();
	connectEvents();
})();
