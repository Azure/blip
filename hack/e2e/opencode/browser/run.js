"use strict";

// End-to-end smoke test for the Blip Chat UI. The auth shim in front of the
// service injects the identity header, so Playwright deliberately sends no
// X-Forwarded-User header of its own.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const TURN_COMPLETE = "turn complete";

function env(name, fallback) {
	const value = process.env[name];
	return value !== undefined && value.trim() !== "" ? value : fallback;
}

function intEnv(name, fallback) {
	const raw = process.env[name];
	if (!raw) return fallback;
	const value = Number(raw);
	if (!Number.isFinite(value) || value <= 0) return fallback;
	return Math.floor(value);
}

function makeNonce(length) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	const bytes = crypto.randomBytes(length);
	let out = "";
	for (let i = 0; i < length; i++) out += alphabet[bytes[i] % alphabet.length];
	return out;
}

function delay(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function withNamespace(pathname, namespace) {
	const sep = pathname.includes("?") ? "&" : "?";
	return pathname + sep + "namespace=" + encodeURIComponent(namespace);
}

function sessionPath(name) {
	return "/api/sessions/" + encodeURIComponent(name);
}

function loadPlaywright() {
	const moduleName = env("PLAYWRIGHT_MODULE", "playwright");
	try {
		return require(moduleName);
	} catch (err) {
		throw new Error(
			`could not load Playwright module ${JSON.stringify(moduleName)}: ${err.message}`,
		);
	}
}

async function fetchJson(page, url, init) {
	return page.evaluate(
		async ({ url, init }) => {
			const res = await fetch(url, init || {});
			let data = null;
			try {
				data = await res.json();
			} catch (_) {
				// Some error responses have no JSON body.
			}
			return { ok: res.ok, status: res.status, data };
		},
		{ url, init },
	);
}

async function waitForProfileOption(page, profile, timeoutMs) {
	await page.waitForFunction(
		(profile) => {
			const select = document.getElementById("new-profile");
			return (
				!!select &&
				Array.prototype.some.call(
					select.options,
					(option) => option.value === profile,
				)
			);
		},
		profile,
		{ timeout: timeoutMs, polling: 100 },
	);
}

async function setNamespace(page, namespace, profile, timeoutMs) {
	await page.evaluate((namespace) => {
		const input = document.getElementById("ns");
		if (input.value === namespace) return;
		input.value = namespace;
		input.dispatchEvent(new Event("change", { bubbles: true }));
	}, namespace);
	await waitForProfileOption(page, profile, timeoutMs);
}

async function createSession(page, cfg) {
	await page.locator("#new").click();
	await page.locator("#new-title").fill(cfg.title);
	await page.locator("#new-profile").selectOption(cfg.profile);
	await page.locator("#new-base").fill(cfg.base);
	await page.locator("#create-ok").click();

	const active = page.locator("#sessions li.active[data-name]");
	await active.waitFor({ state: "visible" });
	const name = await active.getAttribute("data-name");
	if (!name) throw new Error("created session has no data-name");
	return name;
}

async function verifySessionTitle(page, name, title, namespace) {
	const listing = await fetchJson(
		page,
		withNamespace("/api/sessions", namespace),
	);
	if (!listing.ok) {
		throw new Error(`session listing failed with HTTP ${listing.status}`);
	}
	if (!Array.isArray(listing.data)) {
		throw new Error("session listing is not an array");
	}
	const found = listing.data.some(
		(session) => session.name === name && session.title === title,
	);
	if (!found) {
		throw new Error(
			`session ${JSON.stringify(name)} with title ${JSON.stringify(title)} is missing from the listing`,
		);
	}
}

async function waitForComposer(page, timeoutMs) {
	await page.waitForFunction(
		() => {
			const send = document.getElementById("send");
			const text = document.getElementById("text");
			return !!send && !!text && !send.disabled && !text.disabled;
		},
		undefined,
		{ timeout: timeoutMs, polling: 100 },
	);
}

async function sendPrompt(page, prompt) {
	await page.locator("#text").fill(prompt);
	await page.locator("#send").click();
}

async function waitForAgentNonce(page, nonce, timeoutMs) {
	await page.waitForFunction(
		(nonce) => {
			const messages = document.querySelectorAll(
				"#transcript .msg.agent",
			);
			return Array.prototype.some.call(messages, (message) =>
				(message.textContent || "").includes(nonce),
			);
		},
		nonce,
		{ timeout: timeoutMs, polling: 100 },
	);
}

async function waitForTurnComplete(page, expected, timeoutMs) {
	await page.waitForFunction(
		({ expected, needle }) => {
			const messages = document.querySelectorAll(
				"#transcript .msg.system",
			);
			const text = Array.prototype.map
				.call(messages, (message) => message.textContent || "")
				.join("\n");
			let count = 0;
			let index = 0;
			while ((index = text.indexOf(needle, index)) !== -1) {
				count++;
				index += needle.length;
			}
			return count >= expected;
		},
		{ expected, needle: TURN_COMPLETE },
		{ timeout: timeoutMs, polling: 100 },
	);
}

async function runTurn(page, nonce, expectedTurn, timeoutMs) {
	const prompt = `Reply with exactly: E2E_OPENCODE_${nonce}. Do not use any tools.`;
	await sendPrompt(page, prompt);
	await waitForAgentNonce(page, nonce, timeoutMs);
	await waitForTurnComplete(page, expectedTurn, timeoutMs);
}

async function getSession(page, name, namespace) {
	const res = await fetchJson(
		page,
		withNamespace(sessionPath(name), namespace),
	);
	if (!res.ok || !res.data || typeof res.data !== "object") {
		throw new Error(
			`session ${JSON.stringify(name)} lookup failed with HTTP ${res.status}`,
		);
	}
	return res.data;
}

async function stopSession(page, name, namespace) {
	try {
		const res = await fetchJson(
			page,
			withNamespace(sessionPath(name) + "/stop", namespace),
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: "{}",
			},
		);
		if (!res.ok) {
			console.error(`warning: stop returned HTTP ${res.status}`);
		}
	} catch (err) {
		console.error(`warning: stop request failed: ${err.message}`);
	}
}

async function waitForNotRunning(page, name, namespace, timeoutMs) {
	const url = withNamespace(sessionPath(name), namespace);
	const deadline = Date.now() + timeoutMs;
	let last = "no response";
	for (;;) {
		let res;
		try {
			res = await fetchJson(page, url);
		} catch (err) {
			last = `request failed: ${err.message}`;
			res = null;
		}
		if (res && res.ok && res.data && res.data.running === false) return;
		if (res && res.ok) {
			last = `running=${JSON.stringify(res.data && res.data.running)}`;
		} else if (res) {
			last = `HTTP ${res.status}`;
		}
		if (Date.now() >= deadline) {
			throw new Error(
				`session ${JSON.stringify(name)} was still running after ${timeoutMs}ms (${last})`,
			);
		}
		await delay(500);
	}
}

async function stopTracing(context, tracePath) {
	try {
		await context.tracing.stop({ path: tracePath });
	} catch (err) {
		console.error(`warning: could not save trace: ${err.message}`);
	}
}

async function main() {
	const cfg = {
		url: env("BLIP_E2E_URL", "http://127.0.0.1:18080"),
		profile: env("BLIP_E2E_PROFILE", "opencode"),
		base: env("BLIP_E2E_BASE", "e2e-opencode-base"),
		namespace: env("BLIP_E2E_NAMESPACE", "default"),
		titlePrefix: env("BLIP_E2E_TITLE", "opencode-e2e"),
		artifacts: path.resolve(
			env("BLIP_E2E_ARTIFACTS", "test-results"),
		),
		timeoutMs: intEnv("BLIP_E2E_TIMEOUT_MS", 300000),
	};
	cfg.title = `${cfg.titlePrefix}-${Date.now()}`;
	cfg.resultFile = path.resolve(
		env("BLIP_E2E_RESULT_FILE", path.join(cfg.artifacts, "result.json")),
	);
	cfg.traceFile = path.join(cfg.artifacts, "trace.zip");
	cfg.failurePng = path.join(cfg.artifacts, "failure.png");
	cfg.failureHtml = path.join(cfg.artifacts, "failure.html");

	let nonce1 = makeNonce(12);
	let nonce2 = makeNonce(12);
	while (nonce2 === nonce1) nonce2 = makeNonce(12);

	fs.mkdirSync(cfg.artifacts, { recursive: true });

	const { chromium } = loadPlaywright();
	let browser = null;
	let context = null;
	let page = null;
	let tracing = false;

	try {
		browser = await chromium.launch({ headless: true });
		context = await browser.newContext();
		await context.tracing.start({ screenshots: true, snapshots: true });
		tracing = true;

		page = await context.newPage();
		page.setDefaultTimeout(cfg.timeoutMs);
		page.setDefaultNavigationTimeout(cfg.timeoutMs);

		await page.goto(cfg.url, { waitUntil: "domcontentloaded" });
		// Let the initial session/profile loads settle before changing the
		// namespace, otherwise their responses could race the new ones.
		await page.waitForLoadState("networkidle");
		await setNamespace(
			page,
			cfg.namespace,
			cfg.profile,
			cfg.timeoutMs,
		);

		const sessionName = await createSession(page, cfg);
		await verifySessionTitle(
			page,
			sessionName,
			cfg.title,
			cfg.namespace,
		);

		await waitForComposer(page, cfg.timeoutMs);
		await runTurn(page, nonce1, 1, cfg.timeoutMs);
		const firstSession = await getSession(
			page,
			sessionName,
			cfg.namespace,
		);

		// Stop the first Blip and wait for it to wind down so the second turn
		// cannot race against a still-running generation.
		await stopSession(page, sessionName, cfg.namespace);
		await waitForNotRunning(
			page,
			sessionName,
			cfg.namespace,
			Math.min(30000, cfg.timeoutMs),
		);

		await runTurn(page, nonce2, 2, cfg.timeoutMs);
		const secondSession = await getSession(
			page,
			sessionName,
			cfg.namespace,
		);

		const result = {
			sessionName,
			title: cfg.title,
			namespace: cfg.namespace,
			profile: cfg.profile,
			base: cfg.base,
			nonce1,
			nonce2,
			acpSessionId1: firstSession.acpSessionId || "",
			acpSessionId2: secondSession.acpSessionId || "",
			generation1: firstSession.generation,
			generation2: secondSession.generation,
			url: cfg.url,
		};
		fs.mkdirSync(path.dirname(cfg.resultFile), { recursive: true });
		fs.writeFileSync(
			cfg.resultFile,
			JSON.stringify(result, null, 2) + "\n",
		);
		console.log("BLIP_E2E_RESULT " + JSON.stringify(result));

		if (tracing) {
			await stopTracing(context, cfg.traceFile);
			tracing = false;
		}
	} catch (err) {
		try {
			if (page) {
				await page.screenshot({
					path: cfg.failurePng,
					fullPage: true,
				});
				fs.writeFileSync(cfg.failureHtml, await page.content());
			}
		} catch (artifactErr) {
			console.error(
				`warning: could not save failure artifacts: ${artifactErr.message}`,
			);
		}
		if (context && tracing) {
			await stopTracing(context, cfg.traceFile);
			tracing = false;
		}
		console.error(err && err.stack ? err.stack : String(err));
		process.exitCode = 1;
	} finally {
		if (browser) {
			try {
				await browser.close();
			} catch (closeErr) {
				console.error(
					`warning: could not close browser: ${closeErr.message}`,
				);
			}
		}
	}
}

main().catch((err) => {
	console.error(err && err.stack ? err.stack : String(err));
	process.exit(1);
});
