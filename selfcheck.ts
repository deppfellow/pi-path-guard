/**
 * pi-path-guard selfcheck (SBX-2 unit box)
 *
 * Feeds synthetic tool calls through the same handler the extension registers,
 * asserting allow, block, and rewrite outcomes against the real fence.json.
 * Run from the repo root: npx tsx pi/extensions/pi-path-guard/selfcheck.ts
 */
import assert from "node:assert/strict";
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	blockMessage,
	buildFence,
	checkPath,
	createHandler,
	extensionDir,
	rewriteBash,
	shSingleQuote,
} from "./index.js";

const dir = extensionDir();
const worktree = resolve(dir, "..", "..", "..");
const home = homedir();

const fence = buildFence({ cwd: worktree, configPath: join(dir, "fence.json"), sessionTag: "selfcheck", env: {} });
const workerFence = buildFence({ cwd: worktree, configPath: join(dir, "fence.json"), sessionTag: "selfcheck-worker", env: { SBX_AGENT_ROLE: "worker" } });
const handle = (toolName: string, input: Record<string, unknown>) =>
	createHandler(fence)({ toolName, input }, worktree);
const handleAsWorker = (toolName: string, input: Record<string, unknown>) =>
	createHandler(workerFence)({ toolName, input }, worktree);

function expectBlock(v: { block: true; reason: string } | undefined): { block: true; reason: string } {
	assert.ok(v, "expected a block verdict");
	assert.ok(v.block);
	return v;
}

let passed = 0;
function check(name: string, fn: () => void): void {
	fn();
	passed++;
	console.log(`ok - ${name}`);
}

const arena = "/tmp/sbx-selfcheck";
rmSync(arena, { recursive: true, force: true });
mkdirSync(join(arena, "sub"), { recursive: true });
writeFileSync(join(arena, "in-fence.txt"), "hello");
symlinkSync("/etc", join(arena, "evil-link"));

check("fence.json keeps host passthrough disabled and dropTools empty", () => {
	assert.equal(fence.config.hostPassthrough.enabled, false);
	assert.deepEqual(fence.config.hostPassthrough.commandPrefixes, []);
	assert.deepEqual(fence.config.dropTools, []);
	assert.ok(fence.config.shipPattern.length > 0);
});

check("fence arms with worktree, repo, ~/dotfiles and /tmp roots", () => {
	const roots = fence.roots;
	assert.ok(roots.some((r) => worktree.startsWith(r)), `worktree ${worktree} under one of ${roots.join(", ")}`);
	assert.ok(roots.includes(resolve(home, "dotfiles")), "root ~/dotfiles");
	assert.ok(roots.includes("/tmp"), "root /tmp");
});

check("config schema: pathArgTools fences the fff search tools", () => {
	assert.deepEqual(fence.config.pathArgTools.fffind, ["path"]);
	assert.deepEqual(fence.config.pathArgTools.ffgrep, ["path"]);
	assert.ok("worker" in fence.config.perAgent && "verifier" in fence.config.perAgent);
});

check("arming: default role bash=off, worker and verifier stay boxed", () => {
	assert.equal(fence.role, "default");
	assert.equal(fence.config.perAgent.default.bash, "off");
	assert.equal(fence.config.perAgent.worker.bash, "box");
	assert.equal(fence.config.perAgent.verifier.bash, "box");
	assert.equal(workerFence.role, "worker");
});

check("role selection: marker file picks up the role when env is absent", () => {
	const markerDir = join(arena, "marker-repo");
	mkdirSync(join(markerDir, ".pi"), { recursive: true });
	writeFileSync(join(markerDir, ".pi", "agent-role"), "verifier\n");
	const markerFence = buildFence({ cwd: markerDir, configPath: join(dir, "fence.json"), sessionTag: "selfcheck-marker", env: {} });
	assert.equal(markerFence.role, "verifier");
});

check("role selection: env beats the marker file, unknown values land on default", () => {
	const markerDir = join(arena, "marker-repo");
	const envFence = buildFence({ cwd: markerDir, configPath: join(dir, "fence.json"), sessionTag: "selfcheck-env", env: { SBX_AGENT_ROLE: "worker" } });
	assert.equal(envFence.role, "worker");
	writeFileSync(join(markerDir, ".pi", "agent-role"), "stranger");
	const unknownFence = buildFence({ cwd: markerDir, configPath: join(dir, "fence.json"), sessionTag: "selfcheck-unknown", env: {} });
	assert.equal(unknownFence.role, "default");
});

check("allow: read inside the worktree", () => {
	const v = handle("read", { path: join(worktree, "pi", "AGENTS.md") });
	assert.equal(v, undefined);
});

check("allow: read inside /tmp arena", () => {
	assert.equal(handle("read", { path: join(arena, "in-fence.txt") }), undefined);
});

check("allow: ~/dotfiles path", () => {
	assert.equal(handle("read", { path: "~/dotfiles/pi/AGENTS.md" }), undefined);
});

check("allow: relative path resolves against cwd", () => {
	assert.equal(handle("ls", { path: "pi/extensions" }), undefined);
});

check("allow: missing path argument falls back to cwd (in fence here)", () => {
	assert.equal(handle("grep", { pattern: "x" }), undefined);
});

check("block: /etc/passwd names the roots and the escape hatch", () => {
	const v = expectBlock(handle("read", { path: "/etc/passwd" }));
	assert.match(v.reason, /\/etc\/passwd/);
	assert.match(v.reason, /Allowed roots:/);
	assert.match(v.reason, /park the ticket BLOCKED/);
	assert.match(blockMessage(fence, { ok: false, resolved: "/etc/passwd", why: "x" }), /park the ticket BLOCKED/);
});

check("block: write to ~ outside the fence", () => {
	expectBlock(handle("write", { path: "~/deleteme.txt", content: "x" }));
});

check("block: ~/.ssh/config", () => {
	expectBlock(handle("read", { path: "~/.ssh/config" }));
});

check("block: traversal escape", () => {
	const v = checkPath(fence, "../../../etc/passwd", arena);
	assert.equal(v.ok, false);
});

check("block: symlink escape through an in-fence link", () => {
	expectBlock(handle("read", { path: join(arena, "evil-link", "passwd") }));
});

check("block: fffind path argument is fenced", () => {
	expectBlock(handle("fffind", { pattern: "*.env", path: "/etc" }));
});

check("rewrite: plain command is boxed whole", () => {
	const v = rewriteBash(fence, "ls -la", worktree);
	assert.equal(v.action, "box");
	if (v.action === "box") {
		assert.ok(v.command.startsWith(fence.sandboxRun));
		assert.ok(v.command.includes(`-- bash -c ${shSingleQuote("ls -la")}`));
	}
});

check("rewrite: compound chain runs in the box, not on the host", () => {
	const cmd = "git status && rm -rf /tmp/should-not-matter-hostside";
	const v = rewriteBash(fence, cmd, worktree);
	assert.equal(v.action, "box");
	if (v.action === "box") assert.ok(v.command.includes(shSingleQuote(cmd)));
});

check("rewrite: single quotes survive the boxing round-trip", () => {
	const cmd = "echo 'it'" + String.fromCharCode(39) + "s \"fine\" $(boom)";
	const v = rewriteBash(fence, cmd, worktree);
	assert.equal(v.action, "box");
	if (v.action === "box") {
		const quoted = v.command.slice(v.command.indexOf("'") + 1, v.command.lastIndexOf("'"));
		assert.equal(quoted.replace(/'\\''/g, "'"), cmd);
	}
});

check("rewrite: pre-boxed sandbox-run -- command is normalized, not nested", () => {
	const v = rewriteBash(fence, "sandbox-run -- echo hi", worktree);
	assert.equal(v.action, "box");
	if (v.action === "box") assert.equal(v.command, `${fence.sandboxRun} -- bash -c ${shSingleQuote("echo hi")}`);
});

check("rewrite: pasta opt-in survives boxing, flagless default stays netless", () => {
	const pasta = rewriteBash(fence, "sandbox-run --network pasta -- apk fetch nodejs", worktree);
	assert.equal(pasta.action, "box");
	if (pasta.action === "box") {
		assert.ok(pasta.command.includes("--network pasta"), pasta.command);
		assert.ok(pasta.command.includes(shSingleQuote("apk fetch nodejs")), pasta.command);
	}
	const plain = rewriteBash(fence, "sandbox-run -- echo hi", worktree);
	assert.equal(plain.action, "box");
	if (plain.action === "box") assert.ok(!plain.command.includes("--network"), plain.command);
});

check("ship: exact fixed argv form passes through", () => {
	const v = rewriteBash(fence, `sandbox-run --ship -t 'SBX-2 test title' -b 'body text'`, worktree);
	assert.equal(v.action, "ship");
	if (v.action === "ship") assert.ok(v.command.startsWith(fence.sandboxRun));
});

check("ship: cd-to-session-cwd prefix is normalized away", () => {
	const v = rewriteBash(fence, `cd '${worktree}' && sandbox-run --ship -t 'T' -b 'B'`, worktree);
	assert.equal(v.action, "ship");
	if (v.action === "ship") assert.match(v.command, / --ship -t 'T' -b 'B'$/);
});

check("block: cd elsewhere + ship is refused, not boxed", () => {
	const v = rewriteBash(fence, `cd /tmp && sandbox-run --ship -t 'T' -b 'B'`, worktree);
	assert.equal(v.action, "block");
});

check("block: ship attempt buried in a chain is refused, not boxed", () => {
	const v = rewriteBash(fence, `echo x && sandbox-run --ship -t 'T' -b 'B'`, worktree);
	assert.equal(v.action, "block");
});

check("ship: substitution inside single quotes stays literal argv (safe)", () => {
	const v = rewriteBash(fence, `sandbox-run --ship -t '$(evil)' -b 'x'`, worktree);
	assert.equal(v.action, "ship");
});

check("block: ship with double quotes (not the fixed form)", () => {
	const v = rewriteBash(fence, `sandbox-run --ship -t "double" -b 'x'`, worktree);
	assert.equal(v.action, "block");
});

check("block: ship with trailing host command", () => {
	const v = rewriteBash(fence, `sandbox-run --ship -t 'a' -b 'b'; rm -rf /`, worktree);
	assert.equal(v.action, "block");
});

check("block: force push never reaches the host unboxed", () => {
	const v = rewriteBash(fence, "git push --force origin main", worktree);
	assert.equal(v.action, "box");
});

check("off: default role skips bash interception entirely", () => {
	const input: Record<string, unknown> = { command: "echo host-side && rm -rf /" };
	assert.equal(handle("bash", input), undefined);
	assert.equal(input.command, "echo host-side && rm -rf /", "command must reach the host byte-for-byte");
});

check("bash tool call end-to-end: command input is replaced with the boxed form", () => {
	const input: Record<string, unknown> = { command: "echo ok" };
	assert.equal(handleAsWorker("bash", input), undefined);
	assert.equal(input.command, `${fence.sandboxRun} -- bash -c 'echo ok'`);
});

check("blocked bash via handler returns block reason with roots", () => {
	const v = expectBlock(handleAsWorker("bash", { command: `sandbox-run --ship -t 'a' -b 'b' && echo nope` }));
	assert.match(v.reason, /Allowed roots:/);
});

console.log(`\nselfcheck: ${passed} checks passed`);
