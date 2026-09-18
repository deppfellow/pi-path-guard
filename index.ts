/**
 * pi-path-guard (SBX-2, armed by SBX-3)
 *
 * Two fences over the pi agent fleet:
 * 1. File tools (read, write, edit, grep, find, ls, plus the path-argument
 *    tools named in fence.json) may only touch paths under the fence roots.
 * 2. Every bash call is rewritten to execute inside the sandbox-run box.
 *    There is no host-side command passthrough; the only host egress is the
 *    fixed argv form `sandbox-run --ship -t 'TITLE' -b 'BODY'`.
 *
 * Bash policy is per role: "box" rewrites into the sandbox, "block" refuses
 * bash outright, "off" skips interception entirely (operator sessions run
 * unboxed on the host). fence.json ships default=off, worker/verifier=box.
 *
 * Role selection: SBX_AGENT_ROLE env when the fleet launcher sets it,
 * otherwise the role marker file <cwd>/.pi/agent-role; anything unrecognized
 * lands on the default policy.
 *
 * Config lives in fence.json next to this file and is read once per session.
 * Every decision is appended to the fence log for operator audit.
 * Spec: .docs/plans/sandbox-fleet.md, section "Build the path guard extension".
 */
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface AgentPolicy {
	bash: "box" | "block" | "off";
	extraRoots: string[];
}

export interface FenceConfig {
	version: number;
	roots: string[];
	hostPassthrough: { enabled: boolean; commandPrefixes: string[]; reason: string };
	shipPattern: string;
	shipHint: string;
	pathArgTools: Record<string, string[]>;
	dropTools: string[];
	perAgent: Record<string, AgentPolicy>;
	logFile: string;
}

export interface Fence {
	config: FenceConfig;
	role: string;
	roots: string[];
	rootList: string;
	sandboxRun: string;
	sessionTag: string;
	logFile: string;
}

export type BashVerdict =
	| { action: "ship"; command: string }
	| { action: "box"; command: string }
	| { action: "block"; reason: string };

export type PathVerdict = { ok: true; resolved: string; root: string } | { ok: false; resolved: string; why: string };

export type PathBlock = Extract<PathVerdict, { ok: false }>;

const BUILTIN_PATH_ARGS: Record<string, string[]> = {
	read: ["path"],
	write: ["path"],
	edit: ["path"],
	grep: ["path"],
	find: ["path"],
	ls: ["path"],
};

export function extensionDir(): string {
	return dirname(fileURLToPath(import.meta.url));
}

function expandHome(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/")) return join(homedir(), p.slice(2));
	return p;
}

function realpathPrefix(p: string): string {
	const parts: string[] = [];
	let cur = p;
	for (;;) {
		try {
			return parts.length === 0 ? resolve(realpathSync(cur)) : resolve(realpathSync(cur), ...parts);
		} catch {
			parts.unshift(basename(cur));
			const parent = dirname(cur);
			if (parent === cur) return resolve(p);
			cur = parent;
		}
	}
}

function isInside(child: string, root: string): boolean {
	return child === root || child.startsWith(root + "/");
}

function git(cwd: string, ...args: string[]): string | null {
	try {
		return execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
	} catch {
		return null;
	}
}

function findSandboxRun(startDir: string): string {
	let cur = startDir;
	for (;;) {
		const candidate = join(cur, "scripts", "sandbox-run");
		try {
			realpathSync(candidate);
			return candidate;
		} catch {
			const parent = dirname(cur);
			if (parent === cur) break;
			cur = parent;
		}
	}
	return "sandbox-run";
}

export function loadFenceConfig(configPath: string): FenceConfig {
	const raw = JSON.parse(readFileSync(configPath, "utf8")) as FenceConfig;
	if (raw.hostPassthrough?.enabled) {
		throw new Error("fence.json enables hostPassthrough; that mode was removed from the design (see SBX-2 PR body)");
	}
	return raw;
}

function roleFromMarker(cwd: string, known: Record<string, unknown>): string | null {
	try {
		const marker = readFileSync(join(cwd, ".pi", "agent-role"), "utf8").trim();
		return marker in known ? marker : null;
	} catch {
		return null;
	}
}

export function buildFence(opts: { cwd: string; configPath: string; sessionTag?: string; env?: NodeJS.ProcessEnv }): Fence {
	const config = loadFenceConfig(opts.configPath);
	const env = opts.env ?? process.env;
	const envRole = env.SBX_AGENT_ROLE && env.SBX_AGENT_ROLE in config.perAgent ? env.SBX_AGENT_ROLE : null;
	const role = envRole ?? roleFromMarker(opts.cwd, config.perAgent) ?? "default";
	const policy = config.perAgent[role] ?? config.perAgent.default;

	const roots = new Set<string>();
	for (const r of [...config.roots, ...(policy?.extraRoots ?? [])]) {
		roots.add(realpathPrefix(expandHome(r)));
	}
	const top = git(opts.cwd, "rev-parse", "--show-toplevel");
	if (top) {
		roots.add(realpathPrefix(top));
		const common = git(opts.cwd, "rev-parse", "--git-common-dir");
		if (common) roots.add(realpathPrefix(dirname(resolve(top, common))));
	}

	const list = [...roots];
	return {
		config,
		role,
		roots: list,
		rootList: list.join(", "),
		sandboxRun: findSandboxRun(dirname(opts.configPath)),
		sessionTag: opts.sessionTag ?? `pg-${Date.now().toString(36)}-${process.pid}`,
		logFile: config.logFile,
	};
}

export function checkPath(fence: Fence, raw: string, cwd: string): PathVerdict {
	const trimmed = raw.trim();
	if (trimmed === "~" || /^~[^/]/.test(trimmed)) {
		return { ok: false, resolved: trimmed, why: "~user paths are not resolvable inside the fence" };
	}
	const abs = resolve(cwd, expandHome(trimmed));
	const real = realpathPrefix(abs);
	for (const root of fence.roots) {
		if (isInside(real, root)) return { ok: true, resolved: abs, root };
	}
	return { ok: false, resolved: abs, why: "outside all fence roots" };
}

export function shSingleQuote(s: string): string {
	return `'${s.replace(/'/g, "'\\''")}'`;
}

export function rewriteBash(fence: Fence, command: string, cwd: string): BashVerdict {
	const shipPattern = new RegExp(fence.config.shipPattern);
	const shipAnywhere = /sandbox-run\s+--ship\b/;

	const stripCd = /^(?:cd\s+(?:'([^']*)'|"([^"]*)"|([^\s;&|]+))\s+&&\s+)([\s\S]+)$/.exec(command.trim());
	let effective = command.trim();
	if (stripCd) {
		const target = stripCd[1] ?? stripCd[2] ?? stripCd[3] ?? ".";
		const rest = stripCd[4];
		if (realpathPrefix(resolve(cwd, expandHome(target))) === realpathPrefix(cwd)) {
			effective = rest.trim();
		} else if (shipAnywhere.test(rest)) {
			return { action: "block", reason: `--ship must run from the session cwd (${cwd}); cd somewhere else first is refused` };
		}
	}

	if (shipPattern.test(effective)) {
		return { action: "ship", command: effective.replace(/^sandbox-run\b/, fence.sandboxRun) };
	}
	if (shipAnywhere.test(effective)) {
		return {
			action: "block",
			reason: `--ship form rejected; use exactly: ${fence.config.shipHint} (single-quoted title and body, nothing else on the line)`,
		};
	}
	const boxForm = /^sandbox-run\s+(?:--network\s+(none|pasta)\s+)?--\s+([\s\S]+)$/.exec(effective);
	const network = boxForm?.[1] ? `--network ${boxForm[1]} ` : "";
	const inner = boxForm ? boxForm[2] : effective;
	return { action: "box", command: `${fence.sandboxRun} ${network}-- bash -c ${shSingleQuote(inner)}` };
}

const ESCAPE_HATCH =
	"If a legitimate step stays blocked, park the ticket BLOCKED with a writeup instead of retrying (dispatch-contract escape hatch); workers never retry-spam a fence.";

export function blockMessage(fence: Fence, verdict: PathBlock): string {
	return `Blocked by pi-path-guard: "${verdict.resolved}" is outside the fence (${verdict.why}). ` +
		`Allowed roots: ${fence.rootList}. ${ESCAPE_HATCH}`;
}

function pathArgsFor(toolName: string, fence: Fence): string[] | null {
	if (toolName in BUILTIN_PATH_ARGS) return BUILTIN_PATH_ARGS[toolName];
	if (toolName in fence.config.pathArgTools) return fence.config.pathArgTools[toolName];
	return null;
}

export function appendLog(fence: Fence, entry: Record<string, unknown>): void {
	try {
		appendFileSync(fence.logFile, JSON.stringify({ ts: new Date().toISOString(), session: fence.sessionTag, role: fence.role, ...entry }) + "\n");
	} catch {
		/* logging must never break the session */
	}
}

export function createHandler(fence: Fence) {
	return (event: { toolName: string; input: Record<string, unknown> }, cwd: string): { block: true; reason: string } | undefined => {
		const policy = fence.config.perAgent[fence.role] ?? fence.config.perAgent.default;

		if (fence.config.dropTools.includes(event.toolName)) {
			appendLog(fence, { event: "block", tool: event.toolName, reason: "listed in fence.json dropTools" });
			return { block: true, reason: `Blocked by pi-path-guard: tool "${event.toolName}" is dropped by fence policy (dropTools). ${ESCAPE_HATCH}` };
		}

		if (event.toolName === "bash") {
			const command = typeof event.input.command === "string" ? event.input.command : "";
			if (policy?.bash === "off") {
				appendLog(fence, { event: "off", tool: "bash", command: trimmed(command), reason: `role "${fence.role}" policy bash=off; host bash untouched` });
				return undefined;
			}
			if (policy?.bash === "block") {
				appendLog(fence, { event: "block", tool: "bash", reason: `role "${fence.role}" policy bash=block` });
				return { block: true, reason: `Blocked by pi-path-guard: role "${fence.role}" may not run bash. ${ESCAPE_HATCH}` };
			}
			const verdict = rewriteBash(fence, command, cwd);
			if (verdict.action === "block") {
				appendLog(fence, { event: "block", tool: "bash", command, reason: verdict.reason });
				return { block: true, reason: `Blocked by pi-path-guard: ${verdict.reason}. Allowed roots: ${fence.rootList}. ${ESCAPE_HATCH}` };
			}
			if (verdict.action === "ship") {
				event.input.command = verdict.command;
				appendLog(fence, { event: "ship", tool: "bash", command: trimmed(command), hostCommand: verdict.command });
				return undefined;
			}
			event.input.command = verdict.command;
			appendLog(fence, { event: "rewrite", tool: "bash", command: trimmed(command), boxed: verdict.command });
			return undefined;
		}

		const fields = pathArgsFor(event.toolName, fence);
		if (!fields) return undefined;

		const checked: Record<string, string> = {};
		for (const field of fields) {
			const raw = event.input[field];
			const value = typeof raw === "string" && raw.trim() !== "" ? raw : cwd;
			const verdict = checkPath(fence, value, cwd);
			if (!verdict.ok) {
				appendLog(fence, { event: "block", tool: event.toolName, path: verdict.resolved, reason: verdict.why });
				return { block: true, reason: blockMessage(fence, verdict) };
			}
			checked[field] = verdict.resolved;
		}
		appendLog(fence, { event: "allow", tool: event.toolName, paths: checked });
		return undefined;
	};
}

function trimmed(s: string): string {
	return s.length > 400 ? s.slice(0, 400) + "..." : s.trim();
}

export default function (pi: ExtensionAPI) {
	let fence: Fence | null = null;

	function getFence(ctx: ExtensionContext): Fence {
		if (!fence) {
			fence = buildFence({ cwd: ctx.cwd, configPath: join(extensionDir(), "fence.json") });
		}
		return fence;
	}

	pi.on("session_start", async (_event, ctx) => {
		fence = buildFence({ cwd: ctx.cwd, configPath: join(extensionDir(), "fence.json") });
		appendLog(fence, {
			event: "armed",
			cwd: ctx.cwd,
			roots: fence.roots,
			sandboxRun: fence.sandboxRun,
			logFile: fence.logFile,
			hostPassthrough: fence.config.hostPassthrough.enabled,
		});
	});

	pi.on("tool_call", async (event, ctx) => {
		const f = getFence(ctx);
		return createHandler(f)(event as { toolName: string; input: Record<string, unknown> }, ctx.cwd);
	});
}
