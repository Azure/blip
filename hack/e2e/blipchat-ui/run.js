// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

"use strict";

// Fast browser tests for the Blip Chat UI. internal/blipchat/browser_test.go
// starts a real blipchat server with in-memory Kubernetes and agent fakes and
// runs this script with the server's base URL. The fake agent replies
// "echo: <prompt>"; a prompt containing "slow" runs until it is cancelled.
// Each test gets a fresh browser context.

const { chromium } = require("playwright");

const base = process.argv[2];
if (!base) {
	console.error("usage: node run.js <base-url>");
	process.exit(2);
}
const TIMEOUT = 10000;

async function newChat(page) {
	const before = new URL(page.url()).hash;
	await page.click("#new-btn");
	await page.click('#new-menu [role="menuitem"]');
	await page.waitForFunction((h) => location.hash && location.hash !== h, before);
	await page.waitForSelector("#text:not([disabled])");
	return decodeURIComponent(new URL(page.url()).hash.slice(1));
}

async function send(page, text) {
	await page.fill("#text", text);
	await page.press("#text", "Enter");
}

async function waitAgent(page, text) {
	await page.waitForFunction(
		(t) => [...document.querySelectorAll("#transcript .msg.agent .msg-body")].some((el) => el.textContent.includes(t)),
		text,
	);
}

async function transcriptText(page) {
	return page.$eval("#transcript", (el) => el.innerText);
}

async function openChat(page, name) {
	await page.click(`#sessions li[data-name="${name}"] .session-open`);
	await page.waitForFunction((n) => decodeURIComponent(location.hash.slice(1)) === n, name);
	await page.waitForSelector("#text:not([disabled])");
}

function assert(cond, msg) {
	if (!cond) throw new Error(msg);
}

const tests = {
	async "page loads and lists sessions"(page) {
		await page.goto(base);
		await page.waitForFunction(() => document.querySelector("#me").textContent.trim() === "alice");
		const name = await newChat(page);
		await page.goto(base);
		await page.waitForSelector(`#sessions li[data-name="${name}"]`);
	},

	async "new chat from profile menu"(page) {
		await page.goto(base);
		await page.click("#new-btn");
		await page.waitForSelector('#new-menu:not([hidden]) [role="menuitem"]');
		await page.click('#new-menu [role="menuitem"]');
		await page.waitForFunction(() => location.hash.length > 1);
		const name = decodeURIComponent(new URL(page.url()).hash.slice(1));
		await page.waitForSelector(`#sessions li.active[data-name="${name}"]`);
		assert(await page.isHidden("#new-menu"), "menu should close after create");
	},

	async "send prompt and see streamed echo"(page) {
		await page.goto(base);
		await newChat(page);
		await send(page, "hello there");
		await page.waitForSelector("#transcript .msg.user");
		await waitAgent(page, "echo: hello there");
		assert(await page.inputValue("#text") === "", "composer should clear after send");
		await page.waitForFunction(() => document.querySelector("#status").textContent === "idle");
	},

	async "title propagates to sidebar"(page) {
		await page.goto(base);
		const name = await newChat(page);
		await send(page, "title propagation check");
		await waitAgent(page, "echo: title propagation check");
		await page.waitForFunction(
			(n) => (document.querySelector(`#sessions li[data-name="${n}"] .session-title`) || {}).textContent?.includes("title propagation"),
			name,
		);
		await page.waitForFunction(() => document.querySelector("#title").textContent.includes("title propagation"));
	},

	async "reload restores history"(page) {
		await page.goto(base);
		await newChat(page);
		await send(page, "first message");
		await waitAgent(page, "echo: first message");
		await send(page, "second message");
		await waitAgent(page, "echo: second message");
		await page.reload();
		await waitAgent(page, "echo: second message");
		const text = await transcriptText(page);
		assert(text.includes("first message") && text.includes("echo: first message"), "history lost after reload");
		assert((text.match(/echo: second message/g) || []).length === 1, "reply duplicated after reload");
	},

	async "reload while sending keeps the prompt"(page) {
		await page.goto(base);
		await newChat(page);
		await send(page, "sent before reload");
		await page.reload();
		await waitAgent(page, "echo: sent before reload");
	},

	async "deep link opens the chat"(page, context) {
		await page.goto(base);
		const name = await newChat(page);
		await send(page, "deep link body");
		await waitAgent(page, "echo: deep link body");
		const other = await context.newPage();
		await other.goto(`${base}/#${encodeURIComponent(name)}`);
		await waitAgent(other, "echo: deep link body");
		await other.waitForSelector(`#sessions li.active[data-name="${name}"]`);
	},

	async "deep link to a missing chat shows an error"(page) {
		await page.goto(`${base}/#no-such-chat`);
		await page.waitForFunction(() => /could not open/i.test(document.querySelector("#transcript").innerText));
		assert(await page.isDisabled("#text"), "composer should stay disabled");
	},

	async "rapid switching shows the right transcript"(page) {
		await page.goto(base);
		const a = await newChat(page);
		await send(page, "alpha only");
		await waitAgent(page, "echo: alpha only");
		const b = await newChat(page);
		await send(page, "bravo only");
		await waitAgent(page, "echo: bravo only");
		for (let i = 0; i < 7; i++) {
			await page.click(`#sessions li[data-name="${i % 2 ? b : a}"] .session-open`);
		}
		// The last click was a. Wait for it to settle, then check no bleed.
		await page.waitForFunction((n) => decodeURIComponent(location.hash.slice(1)) === n, a);
		await waitAgent(page, "echo: alpha only");
		await page.waitForTimeout(500);
		let text = await transcriptText(page);
		assert(!text.includes("bravo"), "chat a shows chat b's transcript");
		assert((text.match(/echo: alpha only/g) || []).length === 1, "chat a transcript duplicated");
		await openChat(page, b);
		await waitAgent(page, "echo: bravo only");
		await page.waitForTimeout(300);
		text = await transcriptText(page);
		assert(!text.includes("alpha"), "chat b shows chat a's transcript");
	},

	async "cancel a running turn"(page) {
		await page.goto(base);
		await newChat(page);
		await send(page, "slow task");
		await waitAgent(page, "working on it");
		await page.waitForSelector("#cancel:not([hidden]):not([disabled])");
		await page.click("#cancel");
		await page.waitForFunction(() => document.querySelector("#status-dot").dataset.state !== "running");
		await page.waitForSelector("#text:not([disabled])");
		await send(page, "after cancel");
		await waitAgent(page, "echo: after cancel");
	},

	async "queued prompt runs after the current turn"(page) {
		await page.goto(base);
		await newChat(page);
		await send(page, "wait first");
		await page.waitForSelector("#cancel:not([hidden])");
		await send(page, "queued second");
		await waitAgent(page, "echo: queued second");
		const text = await transcriptText(page);
		const first = text.indexOf("echo: wait first");
		assert(first >= 0 && first < text.indexOf("echo: queued second"), "replies out of order");
	},

	async "cancel drops a queued prompt"(page) {
		await page.goto(base);
		await newChat(page);
		await send(page, "slow queue head");
		await waitAgent(page, "working on it");
		await send(page, "dropped follow-up");
		await page.click("#cancel");
		await page.waitForFunction(() => document.querySelector("#status").textContent === "idle");
		await page.waitForTimeout(1500);
		assert(!(await transcriptText(page)).includes("echo: dropped follow-up"), "cancelled queue still ran");
	},

	async "draft survives switching chats"(page) {
		await page.goto(base);
		const a = await newChat(page);
		await page.fill("#text", "unsent draft for a");
		const b = await newChat(page);
		assert(await page.inputValue("#text") === "", "draft leaked into the new chat");
		await page.fill("#text", "draft b");
		await openChat(page, a);
		assert(await page.inputValue("#text") === "unsent draft for a", "draft for a lost");
		await openChat(page, b);
		assert(await page.inputValue("#text") === "draft b", "draft for b lost");
	},

	async "SSE reconnect after the stream drops"(page) {
		await page.goto(base);
		await newChat(page);
		await send(page, "before drop");
		await waitAgent(page, "echo: before drop");
		const res = await page.request.post(`${base}/__test/drop-events`);
		const { dropped } = await res.json();
		assert(dropped > 0, "no event stream was open to drop");
		// The UI reconnects after a 1s backoff; the next reply must still arrive
		// once, and earlier frames must not be replayed.
		await send(page, "after drop");
		await waitAgent(page, "echo: after drop");
		await page.waitForTimeout(1500);
		const text = await transcriptText(page);
		assert((text.match(/echo: before drop/g) || []).length === 1, "frames replayed after reconnect");
		assert((text.match(/echo: after drop/g) || []).length === 1, "reply duplicated after reconnect");
	},
};

async function main() {
	const only = process.env.BLIPCHAT_UI_TEST;
	const browser = await chromium.launch();
	let failed = 0;
	for (const [name, fn] of Object.entries(tests)) {
		if (only && !name.includes(only)) continue;
		const context = await browser.newContext();
		context.setDefaultTimeout(TIMEOUT);
		const page = await context.newPage();
		const errors = [];
		page.on("pageerror", (err) => errors.push(err.message));
		const start = Date.now();
		try {
			await fn(page, context);
			if (errors.length) throw new Error("page errors: " + errors.join("; "));
			console.log(`PASS ${name} (${Date.now() - start}ms)`);
		} catch (err) {
			failed++;
			console.log(`FAIL ${name}: ${err.message.split("\n")[0]}`);
			const where = await page.evaluate(() => ({
				hash: location.hash,
				status: document.querySelector("#status").textContent,
				transcript: document.querySelector("#transcript").innerText,
			})).catch(() => null);
			if (where) console.log(`  at ${where.hash} status=${JSON.stringify(where.status)}\n  transcript: ${JSON.stringify(where.transcript)}`);
		}
		await context.close();
	}
	await browser.close();
	if (failed) {
		console.log(`${failed} browser test(s) failed`);
		process.exit(1);
	}
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
