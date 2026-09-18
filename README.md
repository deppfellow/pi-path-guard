# pi-path-guard

SBX-2 fence extension for the pi agent fleet. Spec: `.docs/plans/sandbox-fleet.md`,
section "Build the path guard extension (SBX-2)".

Two enforced boundaries:

1. **Path fence.** `read`, `write`, `edit`, `grep`, `find`, `ls` (plus the
   extra path-argument tools named in `fence.json`, currently `fffind` and
   `ffgrep`) may only touch paths under the fence roots: the `roots` in
   `fence.json`, the current worktree, the project repo, `~/dotfiles/`, and
   `/tmp`. Blocked calls get a reason naming the allowed roots and the
   dispatch-contract escape hatch (park the ticket BLOCKED with a writeup,
   never retry-spam the fence).
2. **Bash boxing.** Every `bash` tool call is rewritten to run through
   `scripts/sandbox-run -- bash -c '<command>'`, so the whole shell string -
   pipes, `&&`, substitutions - executes inside the rootless podman box.
   There is no host-side command passthrough: the verified attack showed
   `git -C`, `gh repo delete`, and `$()` substitution defeat any prefix rule.
   The only host egress is the exact fixed argv form
   `sandbox-run --ship -t 'TITLE' -b 'BODY'`, matched by the anchored
   `shipPattern`; anything else shaped like `--ship` is blocked with a hint.
   Commands already written as `sandbox-run [flags] -- <cmd>` are normalized
   (the prefix is stripped and the command boxed), never nested.

The runner is resolved at session start as `<repo>/scripts/sandbox-run` by
walking up from this file; once SBX-1's home-manager wiring lands on PATH the
bare name `sandbox-run` is the fallback.

## Config

`fence.json` is read once per session at `session_start`; the active roots are
logged to `logFile` (default `/tmp/pi-path-guard.log`, JSON lines) with an
`armed` event. Every allow, block, rewrite, and ship decision is appended
there for operator audit.

- `roots`: fence roots, `~` expanded.
- `hostPassthrough`: present for the record, hard-disabled. Enabling it makes
  the extension refuse to load.
- `shipPattern` / `shipHint`: the only host-side command form.
- `pathArgTools`: extension tools with path-bearing input fields to fence
  (the MCP spike proved `tool_call` sees `fffind`/`ffgrep`, so they are fenced
  rather than dropped).
- `dropTools`: tools to refuse outright; for anything a future spike proves
  invisible to `tool_call`, also remove it from the worker/verifier toolsets.
- `perAgent`: policy per role from `SBX_AGENT_ROLE` (default `default`):
  `bash: box|block` and `extraRoots`.

## Selfcheck

```
npx tsx pi/extensions/pi-path-guard/selfcheck.ts
```

Feeds synthetic tool calls through the same handler the extension registers
and asserts allow, block, and rewrite outcomes against the real `fence.json`.
`tsx` is a devDependency; the host only has `npx`.

## Loading

Auto-discovery once installed under `~/.pi/agent/extensions/pi-path-guard/`,
or directly: `pi -e /path/to/pi/extensions/pi-path-guard`. Sessions must start
inside the fence: the working directory itself is not an implicit root.
