(() => {
	"use strict";

	const MAX_RECORDS = 500;
	const MAX_ROWS = 160;
	const MINUTE_WINDOW = 30;
	const REDACTED_PATTERN = /\[REDACTED_[A-Z0-9_]+\]/g;
	const records = [];
	const counters = { clean: 0, alerts: 0 };
	const minuteBuckets = new Map();
	const pendingQueue = [];

	let lastSeq = 0;
	let stateReady = false;
	let chart = null;
	let eventSource = null;
	let toastTimer = 0;
	let adminToken = "";

	const elements = {
		status: document.getElementById("streamStatus"),
		statusText: document.getElementById("streamStatusText"),
		modeSelect: document.getElementById("modeSelect"),
		activeMode: document.getElementById("activeMode"),
		caIndicator: document.getElementById("caIndicator"),
		caStatus: document.getElementById("caStatus"),
		caMetadata: document.getElementById("caMetadata"),
		caToggle: document.getElementById("caToggle"),
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

	function riskLevel(event) {
		const level = String(event.risk_level || "UNKNOWN").toUpperCase();
		if (["HIGH", "MEDIUM", "LOW"].includes(level)) return level;
		return event.findings?.length ? "HIGH" : "LOW";
	}

	function isAlertEvent(event) {
		return ["blocked", "sanitized", "engine_unavailable"].includes(String(event.status).toLowerCase())
			|| riskLevel(event) === "HIGH"
			|| Boolean(event.findings?.length);
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

	function requestAdminToken() {
		if (adminToken) return adminToken;
		const token = window.prompt("Token de administrador");
		if (!token) throw new Error("Se requiere el token de administrador");
		adminToken = token;
		return adminToken;
	}

	async function readAdminResponse(response, fallbackMessage) {
		const payload = await response.json().catch(() => ({}));
		if (response.status === 401) {
			adminToken = "";
			throw new Error("Token de administrador no válido");
		}
		if (response.status === 403) throw new Error("Origen no autorizado para esta operación");
		if (!response.ok) throw new Error(payload.error || fallbackMessage);
		return payload;
	}

	function setStreamState(state, label) {
		elements.status.dataset.state = state;
		elements.statusText.textContent = label;
	}

	function updateCA(state) {
		const enabled = Boolean(state.ca_enabled);
		elements.caIndicator.dataset.enabled = String(enabled);
		elements.caStatus.textContent = `CA / MITM ${enabled ? "activa" : "inactiva"}`;
		elements.caToggle.textContent = enabled ? "Desactivar MITM" : "Activar MITM";
		elements.caToggle.disabled = false;
		const details = [state.ca_org || "ProxyGo"];
		if (state.ca_cert_path) details.push(state.ca_cert_path);
		if (state.ca_not_after) details.push(`válida hasta ${new Date(state.ca_not_after).toLocaleDateString("es-MX")}`);
		elements.caMetadata.textContent = details.join(" · ");
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
					{
						label: "Limpias",
						data: Array(MINUTE_WINDOW).fill(0),
						borderColor: "#16a34a",
						backgroundColor: "rgba(22, 163, 74, 0.08)",
						pointRadius: 2,
						pointHoverRadius: 4,
						borderWidth: 2,
						tension: 0.25,
						fill: true
					},
					{
						label: "Alertas",
						data: Array(MINUTE_WINDOW).fill(0),
						borderColor: "#dc2626",
						backgroundColor: "rgba(220, 38, 38, 0.05)",
						pointRadius: 2,
						pointHoverRadius: 4,
						borderWidth: 2,
						tension: 0.25,
						fill: false
					}
				]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				animation: { duration: 200 },
				interaction: { intersect: false, mode: "index" },
				plugins: {
					legend: { display: false },
					tooltip: {
						backgroundColor: "#ffffff",
						borderColor: "#e2e8f0",
						borderWidth: 1,
						titleColor: "#0f172a",
						bodyColor: "#475569",
						padding: 10
					}
				},
				scales: {
					x: {
						grid: { display: false },
						border: { display: false },
						ticks: { color: "#64748b", maxTicksLimit: 8, maxRotation: 0, font: { size: 11 } }
					},
					y: {
						beginAtZero: true,
						border: { display: false },
						grid: { color: "#f1f5f9" },
						ticks: { color: "#64748b", precision: 0, maxTicksLimit: 5, font: { size: 11 } }
					}
				}
			}
		});
	}

	function refreshChart() {
		if (!chart) return;
		const nowMinute = Math.floor(Date.now() / 60_000) * 60_000;
		const visibleMinutes = Array.from({ length: MINUTE_WINDOW }, (_, index) => nowMinute - (MINUTE_WINDOW - index - 1) * 60_000);
		chart.data.labels = visibleMinutes.map(time => new Date(time).toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit", hour12: false }));
		chart.data.datasets[0].data = visibleMinutes.map(time => minuteBuckets.get(time)?.clean || 0);
		chart.data.datasets[1].data = visibleMinutes.map(time => minuteBuckets.get(time)?.alerts || 0);
		chart.update("none");
	}

	function updateMetrics() {
		const currentMinute = Math.floor(Date.now() / 60_000) * 60_000;
		const currentBucket = minuteBuckets.get(currentMinute) || { clean: 0, alerts: 0 };
		elements.requestsPerMinute.textContent = String(currentBucket.clean + currentBucket.alerts);
		elements.cleanCount.textContent = counters.clean.toLocaleString("es-MX");
		elements.alertCount.textContent = counters.alerts.toLocaleString("es-MX");
	}

	function applyLiveEvent(event) {
		if (typeof event.seq === "number") {
			if (event.seq <= lastSeq) return;
			lastSeq = event.seq;
		}

		records.unshift(event);
		if (records.length > MAX_RECORDS) records.length = MAX_RECORDS;

		const timestamp = new Date(event.timestamp || Date.now()).getTime();
		const minute = Math.floor(timestamp / 60_000) * 60_000;
		const alert = isAlertEvent(event);
		const bucket = minuteBuckets.get(minute) || { clean: 0, alerts: 0 };
		bucket[alert ? "alerts" : "clean"] += 1;
		minuteBuckets.set(minute, bucket);

		const oldest = Math.floor(Date.now() / 60_000) * 60_000 - (MINUTE_WINDOW - 1) * 60_000;
		for (const key of minuteBuckets.keys()) {
			if (key < oldest) minuteBuckets.delete(key);
		}
		if (alert) counters.alerts += 1;
		else counters.clean += 1;

		updateMetrics();
		refreshChart();
		renderRows();
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
				row.append(makeCell("host-cell", event.host || "—"));

				const riskCell = document.createElement("td");
				const badge = document.createElement("span");
				const risk = riskLevel(event);
				badge.className = `badge risk-${risk.toLowerCase()}`;
				badge.textContent = risk === "UNKNOWN" ? "SIN DATO" : risk;
				riskCell.append(badge);
				row.append(riskCell);

				const actionCell = document.createElement("td");
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
		elements.visibleRange.textContent = `${visible.length} de ${records.length} eventos recientes`;
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
		elements.detailMeta.textContent = `${time} · ${event.method || "—"} · ${event.host || "host desconocido"}`;
		const risk = riskLevel(event);
		elements.detailRisk.className = `badge risk-${risk.toLowerCase()}`;
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

	async function loadState() {
		try {
			const response = await fetch("/api/state", { headers: { Accept: "application/json" }, cache: "no-store" });
			if (!response.ok) throw new Error("No se pudo cargar el estado del servidor");
			const state = await response.json();
			updateCA(state);

			if (["MONITOR", "SANITIZE", "BLOCK"].includes(state.mode)) {
				elements.modeSelect.value = state.mode;
				elements.activeMode.textContent = state.mode;
			}
			lastSeq = Number(state.seq || 0);
			counters.clean = Number(state.clean_count || 0);
			counters.alerts = Number(state.alert_count || 0);

			minuteBuckets.clear();
			for (const bucket of state.buckets || []) {
				minuteBuckets.set(Number(bucket.minute), {
					clean: Number(bucket.clean || 0),
					alerts: Number(bucket.alerts || 0)
				});
			}

			records.length = 0;
			for (const event of state.events || []) {
				records.push(event);
				if (records.length >= MAX_RECORDS) break;
			}

			stateReady = true;
			while (pendingQueue.length) {
				applyLiveEvent(pendingQueue.shift());
			}
			updateMetrics();
			refreshChart();
			renderRows();
		} catch (error) {
			showToast(error.message, true);
		}
	}

	async function changeCA(enabled) {
		elements.caToggle.disabled = true;
		try {
			const response = await fetch("/api/ca", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Accept: "application/json",
					Authorization: `Bearer ${requestAdminToken()}`
				},
				body: JSON.stringify({ enabled })
			});
			const payload = await readAdminResponse(response, "No se pudo cambiar el estado de MITM");
			updateCA(payload);
			showToast(`MITM ${payload.ca_enabled ? "activado" : "desactivado"}`);
		} catch (error) {
			elements.caToggle.disabled = false;
			showToast(error.message, true);
		}
	}

	async function changeMode(mode) {
		elements.modeSelect.disabled = true;
		try {
			const response = await fetch("/api/mode", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Accept: "application/json",
					Authorization: `Bearer ${requestAdminToken()}`
				},
				body: JSON.stringify({ mode })
			});
			const payload = await readAdminResponse(response, "No se pudo cambiar el modo");
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
		eventSource.onopen = () => {
			setStreamState("connected", "Conectado");
			loadState();
		};
		eventSource.onmessage = message => {
			try {
				const event = JSON.parse(message.data);
				if (event.type === "state") {
					updateCA(event);
					return;
				}
				if (!stateReady) {
					pendingQueue.push(event);
					return;
				}
				applyLiveEvent(event);
			} catch {
				showToast("Evento con formato inválido", true);
			}
		};
		eventSource.onerror = () => setStreamState("disconnected", "Reconectando");
	}

	elements.modeSelect.addEventListener("change", () => changeMode(elements.modeSelect.value));
	elements.caToggle.addEventListener("click", () => changeCA(elements.caToggle.textContent === "Activar MITM"));
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
	window.setInterval(() => {
		updateMetrics();
		refreshChart();
	}, 5000);
	loadState();
	connectEvents();
})();
