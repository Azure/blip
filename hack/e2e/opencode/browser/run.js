// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

"use strict";

// End-to-end smoke test for the Blip Chat UI. The auth shim in front of the
// service injects the identity header, so Playwright deliberately sends no
// X-Forwarded-User header of its own.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

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

function withNamespace(pathname, _scope) {
	// blipchat serves one namespace. The scope argument stays so call sites
	// read naturally, but the API path carries no namespace.
	return pathname;
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
			const menu = document.getElementById("new-menu");
			return (
				!!menu &&
				!menu.hidden &&
				Array.prototype.some.call(
					menu.querySelectorAll("button[data-profile]"),
					(button) => button.dataset.profile === profile,
				)
			);
		},
		profile,
		{ timeout: timeoutMs, polling: 100 },
	);
}

async function selectScope(page, scope) {
	await page.locator(`.tabs [data-scope="${scope}"]`).click();
}

async function createSession(page, cfg) {
	await page.locator("#new-btn").click();
	await waitForProfileOption(page, cfg.profile, cfg.timeoutMs);
	await page.evaluate((profile) => {
		const button = Array.prototype.find.call(
			document.querySelectorAll("#new-menu button[data-profile]"),
			(candidate) => candidate.dataset.profile === profile,
		);
		if (!button) throw new Error("profile button missing: " + profile);
		button.click();
	}, cfg.profile);

	const active = page.locator("#sessions li.active[data-name]");
	await active.waitFor({ state: "visible" });
	const name = await active.getAttribute("data-name");
	if (!name) throw new Error("created session has no data-name");
	return name;
}

async function sessionTitle(page, name) {
	const sessions = await page.evaluate(() => {
		return Array.prototype.map.call(
			document.querySelectorAll("#sessions li"),
			(li) => ({
				name: li.dataset.name,
				title: ((li.querySelector(".session-title") || {}).textContent || "").trim(),
			}),
		);
	});
	const found = sessions.find((session) => session.name === name);
	return found ? found.title : "";
}

// waitForTitle returns any title the header shows once it stops being a
// placeholder, whether the server fallback or an agent-supplied title.
async function waitForTitle(page, timeoutMs) {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const title = ((await page.locator("#title").textContent()) || "").trim();
		if (title && title !== "New chat" && title !== "Blip Chat") return title;
		if (Date.now() >= deadline) return "";
		await delay(250);
	}
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

async function runTurn(page, nonce, name, namespace, timeoutMs) {
	const prompt = `Reply with exactly: E2E_OPENCODE_${nonce}. Do not use any tools.`;
	await sendPrompt(page, prompt);
	await waitForAgentNonce(page, nonce, timeoutMs);
	// The UI no longer renders a "turn complete" transcript marker, and the
	// status header is overwritten when the agent exits. Wait for the session
	// itself instead: the driver closes the agent's stdin at the end of a
	// turn, and ACP agents exit on EOF, which stops the Blip.
	await waitForNotRunning(page, name, namespace, timeoutMs);
	return prompt;
}

async function postMessage(page, name, namespace, text) {
	const res = await fetchJson(
		page,
		withNamespace(sessionPath(name) + "/message", namespace),
		{
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ text }),
		},
	);
	if (!res.ok) {
		throw new Error(`message enqueue failed with HTTP ${res.status}`);
	}
}

// runSpawnTurn queues a warm-up prompt and the spawn prompt back to back.
// opencode connects ACP mcpServers asynchronously after it resumes a session,
// so the first prompt of a turn can be built before the tool catalog includes
// them. The warm-up keeps the agent process alive long enough for the
// connection, and the spawn prompt runs in that same process.
async function runSpawnTurn(
	page,
	name,
	namespace,
	timeoutMs,
	warmupNonce,
	warmupPrompt,
	spawnPrompt,
	spawnNonce,
) {
	await postMessage(page, name, namespace, warmupPrompt);
	await postMessage(page, name, namespace, spawnPrompt);
	await waitForAgentNonce(page, warmupNonce, timeoutMs);
	await waitForAgentNonce(page, spawnNonce, timeoutMs);
	await waitForNotRunning(page, name, namespace, timeoutMs);
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

// waitForChildren polls the session API until the parent has exactly want
// children. It fails on more, since that means the agent over-spawned.
async function waitForChildren(page, parent, namespace, want, timeoutMs) {
	const deadline = Date.now() + timeoutMs;
	let last = "no session listing";
	for (;;) {
		const res = await fetchJson(
			page,
			withNamespace("/api/sessions", namespace),
		);
		if (res.ok && Array.isArray(res.data)) {
			const children = res.data.filter(
				(session) => session.parent === parent,
			);
			if (children.length === want) {
				return children.sort(
					(a, b) => new Date(a.created) - new Date(b.created),
				);
			}
			last = `${children.length} children`;
			if (children.length > want) {
				throw new Error(
					`expected ${want} children of ${JSON.stringify(parent)}, found ${children.length}`,
				);
			}
		} else {
			last = `HTTP ${res.status}`;
		}
		if (Date.now() >= deadline) {
			throw new Error(
				`expected ${want} children of ${JSON.stringify(parent)} after ${timeoutMs}ms (${last})`,
			);
		}
		await delay(500);
	}
}

async function sidebarTree(page) {
	return page.evaluate(() =>
		Array.prototype.map.call(
			document.querySelectorAll("#sessions li[data-name]"),
			(li) => {
				const toggle = li.querySelector(".session-toggle");
				return {
					name: li.dataset.name,
					padding:
						parseFloat(getComputedStyle(li).paddingLeft) || 0,
					expanded:
						!toggle ||
						toggle.getAttribute("aria-expanded") !== "false",
					hidden: li.hidden,
				};
			},
		),
	);
}

// waitForChildRows waits until the sidebar renders each child directly after
// its parent, indented one level, and the parent is expanded.
async function waitForChildRows(page, parent, children, timeoutMs) {
	const deadline = Date.now() + timeoutMs;
	let last = "no session rows";
	for (;;) {
		const rows = await sidebarTree(page);
		const parentIndex = rows.findIndex((row) => row.name === parent);
		const childIndexes = children
			.map((name) => rows.findIndex((row) => row.name === name))
			.sort((a, b) => a - b);
		if (
			parentIndex >= 0 &&
			childIndexes.every((index) => index > parentIndex)
		) {
			const adjacent = childIndexes.every(
				(index, offset) => index === parentIndex + offset + 1,
			);
			const indented = childIndexes.every(
				(index) =>
					rows[index].padding > rows[parentIndex].padding &&
					!rows[index].hidden,
			);
			if (adjacent && indented && rows[parentIndex].expanded) {
				return rows;
			}
			last = `child indexes ${JSON.stringify(childIndexes)} after parent ${parentIndex}`;
		} else {
			last = `parentIndex=${parentIndex} childIndexes=${JSON.stringify(childIndexes)}`;
		}
		if (Date.now() >= deadline) {
			throw new Error(
				`children of ${JSON.stringify(parent)} are not nested in the sidebar after ${timeoutMs}ms (${last})`,
			);
		}
		await delay(250);
	}
}

async function openSessionRow(page, name) {
	await page.evaluate((name) => {
		const li = Array.prototype.find.call(
			document.querySelectorAll("#sessions li[data-name]"),
			(candidate) => candidate.dataset.name === name,
		);
		if (!li) throw new Error("session row missing: " + name);
		const title = li.querySelector(".session-title");
		if (!title) throw new Error("session row has no title button: " + name);
		title.click();
	}, name);
}

async function waitForActiveSession(page, name, timeoutMs) {
	await page.waitForFunction(
		(name) => {
			const active = document.querySelector(
				"#sessions li.active[data-name]",
			);
			return !!active && active.dataset.name === name;
		},
		name,
		{ timeout: timeoutMs, polling: 100 },
	);
}

async function waitForOrigin(page, parent, timeoutMs) {
	await page.waitForFunction(
		(parent) => {
			const origin = document.getElementById("origin");
			return (
				!!origin &&
				!origin.hidden &&
				origin.dataset.parent === parent
			);
		},
		parent,
		{ timeout: timeoutMs, polling: 100 },
	);
}

// waitForAnyAgentNonce returns whichever nonce first appears in the agent
// transcript, so callers do not depend on the order the children were created.
async function waitForAnyAgentNonce(page, nonces, timeoutMs) {
	const handle = await page.waitForFunction(
		(nonces) => {
			const text = Array.prototype.map
				.call(
					document.querySelectorAll("#transcript .msg.agent"),
					(message) => message.textContent || "",
				)
				.join("\n");
			return nonces.find((nonce) => text.includes(nonce)) || false;
		},
		nonces,
		{ timeout: timeoutMs, polling: 100 },
	);
	return handle.jsonValue();
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
		scope: env("BLIP_E2E_SCOPE", "team"),
		artifacts: path.resolve(
			env("BLIP_E2E_ARTIFACTS", "test-results"),
		),
		timeoutMs: intEnv("BLIP_E2E_TIMEOUT_MS", 300000),
		titleWaitMs: intEnv("BLIP_E2E_TITLE_WAIT_MS", 15000),
	};
	cfg.resultFile = path.resolve(
		env("BLIP_E2E_RESULT_FILE", path.join(cfg.artifacts, "result.json")),
	);
	cfg.traceFile = path.join(cfg.artifacts, "trace.zip");
	cfg.failurePng = path.join(cfg.artifacts, "failure.png");
	cfg.failureHtml = path.join(cfg.artifacts, "failure.html");

	let nonce1 = makeNonce(12);
	let nonce2 = makeNonce(12);
	while (nonce2 === nonce1) nonce2 = makeNonce(12);
	let nonce3 = makeNonce(12);
	while (nonce3 === nonce1 || nonce3 === nonce2) nonce3 = makeNonce(12);
	const childNonceA = "E2E_SUBAGENT_" + makeNonce(10);
	let childNonceB = "E2E_SUBAGENT_" + makeNonce(10);
	while (childNonceB === childNonceA) {
		childNonceB = "E2E_SUBAGENT_" + makeNonce(10);
	}
	const warmupNonce = "E2E_WARMUP_" + makeNonce(10);

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
		// Let the initial session load settle before switching tabs,
		// otherwise its response could race the new one.
		await page.waitForLoadState("networkidle");
		await selectScope(page, cfg.scope);

		const sessionName = await createSession(page, cfg);
		await verifySessionTitle(
			page,
			sessionName,
			"",
			cfg.scope,
		);
		const placeholder = ((await page.locator("#title").textContent()) || "").trim();
		if (placeholder !== "New chat" && placeholder !== "Blip Chat") {
			throw new Error(
				`new chat header = ${JSON.stringify(placeholder)}, want "New chat" or "Blip Chat"`,
			);
		}

		await waitForComposer(page, cfg.timeoutMs);
		const firstPrompt = await runTurn(
			page,
			nonce1,
			sessionName,
			cfg.scope,
			cfg.timeoutMs,
		);

		const title = await waitForTitle(page, cfg.titleWaitMs);
		if (!title) {
			throw new Error("chat has no title after the first turn");
		}
		await verifySessionTitle(page, sessionName, title, cfg.scope);
		const header = ((await page.locator("#title").textContent()) || "").trim();
		if (header !== title) {
			throw new Error(
				`header = ${JSON.stringify(header)}, want ${JSON.stringify(title)}`,
			);
		}
		const listed = await sessionTitle(page, sessionName);
		if (listed !== title) {
			throw new Error(
				`sidebar title = ${JSON.stringify(listed)}, want ${JSON.stringify(title)}`,
			);
		}
		if (title !== firstPrompt) {
			// The server names a chat from its first message, so a different
			// title can only come from an agent-supplied rename.
			console.log(
				`chat title ${JSON.stringify(title)} differs from the first prompt; treating it as an agent-supplied rename`,
			);
		}
		const firstSession = await getSession(
			page,
			sessionName,
			cfg.scope,
		);

		// Stop the first Blip and wait for it to wind down so the second turn
		// cannot race against a still-running generation.
		await stopSession(page, sessionName, cfg.scope);
		await waitForNotRunning(
			page,
			sessionName,
			cfg.scope,
			Math.min(30000, cfg.timeoutMs),
		);

		await runTurn(
			page,
			nonce2,
			sessionName,
			cfg.scope,
			cfg.timeoutMs,
		);
		const secondSession = await getSession(
			page,
			sessionName,
			cfg.scope,
		);

		// Ask the agent to fork itself through the blipchat MCP server. The
		// children are independent chats, so this also exercises the parent
		// labels and annotations that the UI nests on.
		const spawnPrompt = [
			"Fork yourself into exactly two child chats now.",
			"Use the spawn_agent tool from the blipchat MCP server; it may be listed as blipchat_spawn_agent.",
			"Call spawn_agent exactly twice, once per child, and do not call any other tool.",
			`First call: profile "opencode", title "E2E child A", prompt ${JSON.stringify(
				`Reply with exactly: ${childNonceA}. Do not use any tools.`,
			)}.`,
			`Second call: profile "opencode", title "E2E child B", prompt ${JSON.stringify(
				`Reply with exactly: ${childNonceB}. Do not use any tools.`,
			)}.`,
			"Do not call get_agent and do not wait for the children.",
			`After both spawn_agent calls return, reply with exactly: E2E_OPENCODE_${nonce3}.`,
		].join("\n");
		await runSpawnTurn(
			page,
			sessionName,
			cfg.scope,
			cfg.timeoutMs,
			warmupNonce,
			`Reply with exactly: ${warmupNonce}. Do not use any tools.`,
			spawnPrompt,
			nonce3,
		);
		const thirdSession = await getSession(
			page,
			sessionName,
			cfg.scope,
		);

		const spawned = await waitForChildren(
			page,
			sessionName,
			cfg.scope,
			2,
			cfg.timeoutMs,
		);
		const childNames = spawned.map((session) => session.name);

		// The sidebar polls for session changes, so children spawned during
		// this turn must appear without a page reload.
		await waitForChildRows(
			page,
			sessionName,
			childNames,
			cfg.timeoutMs,
		);

		const seenChildNonces = new Set();
		const children = [];
		for (const childName of childNames) {
			await openSessionRow(page, childName);
			// Both children share a parent, so the origin banner cannot tell
			// them apart. Wait for the click to make this child active before
			// reading its transcript.
			await waitForActiveSession(page, childName, cfg.timeoutMs);
			await waitForOrigin(page, sessionName, cfg.timeoutMs);
			const childNonce = await waitForAnyAgentNonce(
				page,
				[childNonceA, childNonceB],
				cfg.timeoutMs,
			);
			if (seenChildNonces.has(childNonce)) {
				throw new Error(
					`nonce ${childNonce} appeared in more than one child`,
				);
			}
			seenChildNonces.add(childNonce);
			const child = await getSession(page, childName, cfg.scope);
			if (child.parent !== sessionName) {
				throw new Error(
					`child ${childName} parent = ${JSON.stringify(child.parent)}, want ${JSON.stringify(sessionName)}`,
				);
			}
			if (child.root !== sessionName) {
				throw new Error(
					`child ${childName} root = ${JSON.stringify(child.root)}, want ${JSON.stringify(sessionName)}`,
				);
			}
			if (child.depth !== 1) {
				throw new Error(
					`child ${childName} depth = ${JSON.stringify(child.depth)}, want 1`,
				);
			}
			await waitForNotRunning(
				page,
				childName,
				cfg.scope,
				cfg.timeoutMs,
			);
			children.push({
				name: childName,
				parent: child.parent,
				root: child.root,
				depth: child.depth,
				nonce: childNonce,
				acpSessionId: child.acpSessionId || "",
				generation: child.generation,
				title: child.title || "",
			});
		}
		if (seenChildNonces.size !== 2) {
			throw new Error(
				`expected replies from both children, saw ${seenChildNonces.size}`,
			);
		}

		const result = {
			sessionName,
			title,
			scope: cfg.scope,
			profile: cfg.profile,
			nonce1,
			nonce2,
			nonce3,
			acpSessionId1: firstSession.acpSessionId || "",
			acpSessionId2: secondSession.acpSessionId || "",
			acpSessionId3: thirdSession.acpSessionId || "",
			generation1: firstSession.generation,
			generation2: secondSession.generation,
			generation3: thirdSession.generation,
			children,
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
