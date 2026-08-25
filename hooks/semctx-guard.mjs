#!/usr/bin/env node
// Claude Code PreToolUse guard for semctx (ADR 0007). Advisory by default (never blocks);
// blocks terminal `git commit` / `git push` when guarded mode is enabled and the command is not
// isolated or the current working state has not been verified.
//
// It parses the Bash command STRUCTURALLY (segments + tokens, never a shell eval) and never
// executes PR/agent content. It gates on a diff hash — no analysis runs here.
import { existsSync, lstatSync, readFileSync, readlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, join, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

function unwrapShellBody(text) {
  const body = text.trim();
  const quote = body[0];
  if (quote !== '"' && quote !== "'") return body;
  const closing = body.lastIndexOf(quote);
  return closing > 0 ? body.slice(1, closing) : body.slice(1);
}

function wrappedShellCommand(command) {
  const text = String(command ?? "");
  const assignments = String.raw`(?:env(?:\s+-\S+)*\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*`;
  const patterns = [
    new RegExp(String.raw`(?:^|[;&|\n]\s*)${assignments}(?:bash|sh|zsh)(?:\s+(?!-c\b)\S+)*\s+-c\s+`, "i"),
    new RegExp(String.raw`(?:^|[;&|\n]\s*)${assignments}(?:powershell|pwsh)(?:\.exe)?(?:\s+(?!-(?:command|c)\b)\S+)*\s+-(?:command|c)\s+`, "i"),
    new RegExp(String.raw`(?:^|[;&|\n]\s*)${assignments}cmd(?:\.exe)?(?:\s+(?!\/c\b)\S+)*\s+\/c\s+`, "i"),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match !== null) {
      return { body: unwrapShellBody(text.slice(match.index + match[0].length)), start: match.index };
    }
  }
  return null;
}

function shellCommandBody(command) {
  return wrappedShellCommand(command)?.body ?? null;
}

function envSplitStringBody(command) {
  const text = String(command ?? "").trim();
  const tokens = text.split(/\s+/).filter(Boolean);
  let i = 0;
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i += 1;
  if (executableName(tokens[i]) !== "env" && executableName(tokens[i]) !== "env.exe") return null;
  const splitOption = /(?:^|\s)(?:-S\s+|--split-string(?:=|\s+))/.exec(text);
  if (splitOption === null) return null;
  return unwrapShellBody(text.slice(splitOption.index + splitOption[0].length));
}

function executableName(token) {
  return stripQuotes(token).replace(/\\/g, "/").split("/").pop()?.toLowerCase();
}

const ENV_OPTIONS_WITH_VALUE = new Set([
  "-a",
  "-C",
  "-S",
  "-u",
  "--argv0",
  "--chdir",
  "--split-string",
  "--unset",
]);

function envCommandIndex(tokens, start) {
  if (executableName(tokens[start]) !== "env" && executableName(tokens[start]) !== "env.exe") return start;
  let i = start + 1;
  while (i < tokens.length) {
    const token = stripQuotes(tokens[i]);
    if (token === "--") return i + 1;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token) || !token.startsWith("-")) return i;
    if (ENV_OPTIONS_WITH_VALUE.has(token)) {
      i += 2;
      continue;
    }
    i += 1;
  }
  return i;
}

function gitTokenIndex(tokens) {
  let i = 0;
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i += 1;
  i = envCommandIndex(tokens, i);
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i += 1;
  if (stripQuotes(tokens[i]) === "command") i += 1;
  const executable = executableName(tokens[i]);
  return executable === "git" || executable === "git.exe" ? i : -1;
}

const GIT_GLOBAL_OPTIONS_WITH_VALUE = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--namespace",
  "--super-prefix",
  "--work-tree",
]);

const GIT_RETARGET_OPTIONS = new Set([
  "--git-dir",
  "--namespace",
  "--work-tree",
]);

const GIT_RETARGET_ENV = new Set([
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_REPLACE_REF_BASE",
  "GIT_SHALLOW_FILE",
  "GIT_WORK_TREE",
]);

const GIT_RETARGET_CONFIG = new Set([
  "core.bare",
  "core.worktree",
  "extensions.worktreeconfig",
]);

function gitOptionName(token) {
  const clean = stripQuotes(token);
  const equals = clean.indexOf("=");
  return equals < 0 ? clean : clean.slice(0, equals);
}

function gitOptionConsumesNext(token) {
  const clean = stripQuotes(token);
  return !clean.includes("=") && GIT_GLOBAL_OPTIONS_WITH_VALUE.has(clean);
}

function gitCPath(token, nextToken) {
  const clean = stripQuotes(token);
  if (clean === "-C") return nextToken === undefined ? null : stripQuotes(nextToken);
  return clean.startsWith("-C") && clean.length > 2 ? clean.slice(2) : null;
}

function pathRequiresShellExpansion(token) {
  return /[$~*?{}[\]]/.test(stripQuotes(token));
}

function isRetargetingEnvironmentName(name) {
  const normalized = String(name ?? "").toUpperCase();
  return GIT_RETARGET_ENV.has(normalized) || normalized.startsWith("GIT_CONFIG_");
}

function isRetargetingEnvironmentAssignment(token) {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(String(token ?? ""));
  if (match === null) return false;
  return isRetargetingEnvironmentName(match[1]);
}

function isRetargetingConfig(value) {
  const key = stripQuotes(value).split("=", 1)[0].toLowerCase();
  return GIT_RETARGET_CONFIG.has(key);
}

function envWrapperMakesScopeAmbiguous(tokens, gitIndex) {
  let envIndex = 0;
  while (envIndex < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[envIndex])) envIndex += 1;
  if (executableName(tokens[envIndex]) !== "env" && executableName(tokens[envIndex]) !== "env.exe") return false;
  const envArgs = tokens.slice(envIndex + 1, gitIndex);
  for (let i = 0; i < envArgs.length; i += 1) {
    const token = stripQuotes(envArgs[i]);
    if (token === "-i" || token === "--ignore-environment") return true;
    if (token === "-u" || token === "--unset") {
      if (isRetargetingEnvironmentName(stripQuotes(envArgs[i + 1]))) return true;
      i += 1;
      continue;
    }
    if (
      (token.startsWith("-u") && token.length > 2 && isRetargetingEnvironmentName(token.slice(2)))
      || (token.startsWith("--unset=") && isRetargetingEnvironmentName(token.slice("--unset=".length)))
    ) {
      return true;
    }
    if (
      token === "-C"
      || token === "-S"
      || token === "--chdir"
      || token === "--split-string"
      || (token.startsWith("-C") && token.length > 2)
      || token.startsWith("--chdir=")
      || token.startsWith("--split-string=")
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Whether the command can make Git operate on state other than the structurally resolved cwd.
 * These forms are not evaluated or expanded by the hook, so guarded mode must use the session
 * guard as a fail-closed fallback.
 */
function gitScopeRequiresSessionGuard(command) {
  const text = String(command ?? "");
  if (envSplitStringBody(text) !== null) return true;
  const nested = shellCommandBody(text);
  if (nested !== null && gitScopeRequiresSessionGuard(nested)) return true;

  for (const segment of text.split(/&&|\|\||;|\||\n/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) {
      if (isRetargetingEnvironmentAssignment(tokens[i])) return true;
      i += 1;
    }
    if (stripQuotes(tokens[i]).toLowerCase() === "cd" && tokens[i + 1] !== undefined) {
      if (pathRequiresShellExpansion(tokens[i + 1])) return true;
      continue;
    }

    const gitIndex = gitTokenIndex(tokens);
    if (gitIndex < 0) continue;
    if (envWrapperMakesScopeAmbiguous(tokens, gitIndex)) return true;
    for (let prefix = 0; prefix < gitIndex; prefix += 1) {
      if (isRetargetingEnvironmentAssignment(tokens[prefix])) return true;
    }

    i = gitIndex + 1;
    while (i < tokens.length) {
      const token = stripQuotes(tokens[i]);
      const option = gitOptionName(token);
      const cwdPath = gitCPath(token, tokens[i + 1]);
      if (cwdPath !== null) {
        if (pathRequiresShellExpansion(cwdPath)) return true;
      } else if (option === "-c") {
        if (tokens[i + 1] !== undefined && isRetargetingConfig(tokens[i + 1])) return true;
      } else if (option === "--config-env") {
        const config = token.includes("=") ? token.slice(token.indexOf("=") + 1) : tokens[i + 1];
        if (config !== undefined && isRetargetingConfig(config)) return true;
      } else if (GIT_RETARGET_OPTIONS.has(option) || option === "--bare") {
        return true;
      }
      if (!token.startsWith("-")) break;
      i += gitOptionConsumesNext(token) ? 2 : 1;
    }
  }
  return false;
}

/** Detect a terminal git verb (commit|push) in a shell command, structurally. Returns the verb or null. */
export function isTerminalGitCommand(command) {
  const envSplit = envSplitStringBody(command);
  if (envSplit !== null) {
    const verb = isTerminalGitCommand(envSplit);
    if (verb !== null) return verb;
  }
  const nested = shellCommandBody(command);
  if (nested !== null) {
    const verb = isTerminalGitCommand(nested);
    if (verb !== null) return verb;
  }
  const segments = String(command ?? "").split(/&&|\|\||;|\||\n/);
  for (const seg of segments) {
    const tokens = seg.trim().split(/\s+/).filter(Boolean);
    const gitIndex = gitTokenIndex(tokens);
    if (gitIndex < 0) continue;
    let i = gitIndex + 1;
    while (i < tokens.length) {
      const t = stripQuotes(tokens[i]);
      if (gitOptionConsumesNext(t)) { i += 2; continue; }
      if (t?.startsWith("-")) { i += 1; continue; } // other global flags
      break;
    }
    const sub = stripQuotes(tokens[i]);
    if (sub === "commit" || sub === "push") return sub;
  }
  return null;
}

/**
 * Guarded mode authorizes only one terminal Git operation. Safe cwd prefixes are allowed, but any
 * other compound segment or shell expansion could mutate the repository after the pre-check.
 */
export function isIsolatedTerminalGitCommand(command) {
  const text = String(command ?? "").trim();
  if (text === "" || shellCommandBody(text) !== null || envSplitStringBody(text) !== null) return false;
  if (/\$\(|`|\r|\n|\|\||(?<!\|)\|(?!\|)|;|(?<!&)&(?!&)|[<>]/.test(text)) return false;
  if (gitScopeRequiresSessionGuard(text)) return false;

  const segments = text.split("&&").map((segment) => segment.trim());
  if (segments.some((segment) => segment === "")) return false;
  const terminal = segments.pop();
  if (terminal === undefined || isTerminalGitCommand(terminal) === null) return false;

  for (const prefix of segments) {
    const tokens = prefix.split(/\s+/).filter(Boolean);
    if (tokens.length !== 2 || stripQuotes(tokens[0]).toLowerCase() !== "cd") return false;
    const target = stripQuotes(tokens[1]);
    if (target === "" || pathRequiresShellExpansion(target)) return false;
  }
  return true;
}

/** Strip one layer of surrounding single or double quotes from a shell token. */
function stripQuotes(token) {
  const t = String(token ?? "");
  const q = t[0];
  if (t.length >= 2 && (q === '"' || q === "'") && t[t.length - 1] === q) return t.slice(1, -1);
  return t;
}

/** Resolve `p` (a shell token) against `base`; absolute paths win. */
function resolveUnder(base, p) {
  const clean = stripQuotes(p);
  return isAbsolute(clean) ? resolve(clean) : resolve(base, clean);
}

/**
 * Resolve the directory the terminal git command will actually run in, so the guard evaluates the
 * repo being committed to — not the session cwd. Honors left-to-right `cd <path>` prefixes and
 * git's own `-C <path>` global option, resolved relative to inputCwd. Paths that require shell
 * expansion are deliberately not interpreted here; guarded mode treats their scope as ambiguous
 * and falls back to the session guard. Falls back to inputCwd.
 */
export function resolveGitCwd(command, inputCwd) {
  const text = String(command ?? "");
  const envSplit = envSplitStringBody(text);
  if (envSplit !== null) return resolveGitCwd(envSplit, inputCwd);
  const wrapped = wrappedShellCommand(text);
  if (wrapped !== null) {
    const nestedBase = wrapped.start > 0 ? resolveGitCwd(text.slice(0, wrapped.start), inputCwd) : inputCwd;
    return resolveGitCwd(wrapped.body, nestedBase);
  }
  const segments = text.split(/&&|\|\||;|\||\n/);
  let cwd = inputCwd;
  for (const seg of segments) {
    const tokens = seg.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i += 1; // skip env assignments
    if (tokens[i] === "cd" && tokens[i + 1] !== undefined) {
      cwd = resolveUnder(cwd, tokens[i + 1]);
      continue;
    }
    const gitIndex = gitTokenIndex(tokens);
    if (gitIndex < 0) continue;
    i = gitIndex + 1;
    let gitCwd = cwd;
    while (i < tokens.length) {
      const t = tokens[i];
      const cwdPath = gitCPath(t, tokens[i + 1]);
      if (cwdPath !== null) {
        gitCwd = resolveUnder(gitCwd, cwdPath);
        i += stripQuotes(t) === "-C" ? 2 : 1;
        continue;
      }
      if (t === "-c" && tokens[i + 1] !== undefined) { i += 2; continue; } // -c takes a value, not a path
      if (gitOptionConsumesNext(t)) { i += 2; continue; }
      if (t?.startsWith("-")) { i += 1; continue; }
      break;
    }
    const sub = tokens[i];
    if (sub === "commit" || sub === "push") return gitCwd;
  }
  return cwd;
}

/** Enablement: SEMCTX_GUARD=off strictly disables (wins); =on forces; else .semctx/guard.json {enabled}. */
export function guardEnabled(env, guardJson) {
  const e = String(env?.SEMCTX_GUARD ?? "").toLowerCase();
  if (e === "off" || e === "0" || e === "false") return false;
  if (e === "on" || e === "1" || e === "true") return true;
  return guardJson?.enabled === true;
}

/** Verify command for a shell that has no plugin bundle in reach. */
export const GLOBAL_VERIFY_COMMAND = "semctx verify diff --record";

/** POSIX single-quote: safe for spaces, `$`, backticks, and embedded quotes. */
export function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

/**
 * Absolute path of the plugin-bundled CLI, or null when no bundle is in reach.
 *
 * Claude Code exports CLAUDE_PLUGIN_ROOT to *hook processes* (and to MCP/LSP subprocesses) — it is
 * NOT exported to the agent's shell, and `${CLAUDE_PLUGIN_ROOT}` is a load-time placeholder for
 * skill/hook/MCP fields only. Oh My Pi substitutes `${OMP_PLUGIN_ROOT}` the same way in MCP
 * config. A guard reason string is neither, so the path must be resolved here.
 * Falls back to this hook's own location so a plugin copy without the env var still works.
 */
export function pluginCliPath(env = process.env, exists = existsSync) {
  const candidates = [];
  for (const key of ["CLAUDE_PLUGIN_ROOT", "OMP_PLUGIN_ROOT"]) {
    const declared = String(env?.[key] ?? "").trim();
    if (declared) candidates.push(join(declared, "dist", "semctx.js"));
  }
  candidates.push(resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist", "semctx.js"));
  for (const candidate of candidates) {
    try {
      if (exists(candidate)) return candidate;
    } catch {
      // unreadable candidate: fall through to the next one
    }
  }
  return null;
}

/**
 * Whether a `bun` executable is on PATH. Directory probe only — the guard must stay fast and
 * side-effect free, so it never spawns a process to answer this.
 */
export function bunOnPath(env = process.env, exists = existsSync) {
  const entries = String(env?.PATH ?? "").split(process.platform === "win32" ? ";" : ":");
  const names = process.platform === "win32" ? ["bun.exe", "bun.cmd", "bun"] : ["bun"];
  for (const entry of entries) {
    if (!entry) continue;
    for (const name of names) {
      try {
        if (exists(join(entry, name))) return true;
      } catch {
        // unreadable PATH entry: keep probing
      }
    }
  }
  return false;
}

/**
 * Prefer the plugin-bundled CLI (same release as the MCP runtime) and emit it as an ALREADY
 * RESOLVED, shell-quoted absolute path — the agent runs this string in a shell that does not
 * receive CLAUDE_PLUGIN_ROOT, so a deferred `"$CLAUDE_PLUGIN_ROOT/…"` would expand to `/dist/…`.
 * Fall back to a global `semctx` when no bundle is in reach, or when Bun is absent: this hook runs
 * under Node precisely so guarded mode works on Bun-less machines, and a block message must never
 * name a runtime the user does not have.
 */
export function verifyRecordCommand(env = process.env, exists = existsSync) {
  const cli = pluginCliPath(env, exists);
  if (!cli || !bunOnPath(env, exists)) return GLOBAL_VERIFY_COMMAND;
  return `bun ${shellQuote(cli)} verify diff --record`;
}

/**
 * Pure decision — reads no environment and touches no filesystem.
 * ctx: { enabled, terminalVerb, commandIsolated?, state|null, currentState|null, verifyCommand? }.
 */
export function guardDecision(ctx) {
  if (!ctx.enabled || !ctx.terminalVerb) return { block: false };
  const verifyCmd = ctx.verifyCommand ?? GLOBAL_VERIFY_COMMAND;
  const retry = `then retry the ${ctx.terminalVerb}. (strictly disable: SEMCTX_GUARD=off)`;
  if (ctx.commandIsolated === false) {
    return {
      block: true,
      reason: `semctx guarded mode: git ${ctx.terminalVerb} must be an isolated command; compound commands, shell substitutions, redirections, unexpanded cwd paths, and Git repository retargeting are not authorized.\n${retry}`,
    };
  }
  if (!ctx.state) {
    return { block: true, reason: `semctx guarded mode: no verification on record. Run:\n  ${verifyCmd}\n${retry}` };
  }
  if (
    ctx.state.version !== 2
    || !ctx.state.headCommit
    || !ctx.state.workingStateHash
    || !ctx.currentState
  ) {
    return { block: true, reason: `semctx guarded mode: the verification baseline is legacy, invalid, or unavailable. Re-run:\n  ${verifyCmd}\n${retry}` };
  }
  if (ctx.state.verdict === "BLOCK") {
    return { block: true, reason: `semctx guarded mode: the last verification was BLOCK. Resolve the findings, then re-run:\n  ${verifyCmd}` };
  }
  if (
    ctx.state.headCommit !== ctx.currentState.headCommit
    || ctx.state.workingStateHash !== ctx.currentState.workingStateHash
  ) {
    return { block: true, reason: `semctx guarded mode: the commit or working state changed since the last verification. Re-run:\n  ${verifyCmd}\n${retry}` };
  }
  return { block: false };
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

function frame(hash, label, payload) {
  const bytes = typeof payload === "string" ? Buffer.from(payload, "utf8") : payload;
  hash.update(`${label}\0${bytes.byteLength}\0`, "utf8").update(bytes);
}

/** Capture the same commit + tracked/untracked bytes recorded by `semctx verify diff --record`. */
export function captureVerificationGitState(cwd) {
  const headCommit = execFileSync("git", ["rev-parse", "--verify", "HEAD"], { cwd, encoding: "utf8" }).trim();
  const diff = execFileSync("git", ["diff", "HEAD", "--relative", "--binary", "--no-color", "--", "."], {
    cwd,
    encoding: "buffer",
    maxBuffer: 256 * 1024 * 1024,
  });
  const untracked = execFileSync("git", ["ls-files", "--others", "--exclude-standard", "-z", "--", "."], {
    cwd,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  }).split("\0").filter(Boolean).sort();
  const hash = createHash("sha256");
  frame(hash, "domain", "semctx:verification-working-state:v1");
  frame(hash, "tracked-diff", diff);
  for (const path of untracked) {
    const absolute = resolve(cwd, path);
    const stat = lstatSync(absolute);
    frame(hash, "untracked-path", path.replace(/\\/g, "/"));
    if (stat.isSymbolicLink()) {
      frame(hash, "untracked-kind", "symlink");
      frame(hash, "untracked-target", readlinkSync(absolute));
    } else if (stat.isFile()) {
      frame(hash, "untracked-kind", (stat.mode & 0o111) === 0 ? "file:100644" : "file:100755");
      frame(hash, "untracked-content", readFileSync(absolute));
    } else {
      throw new Error(`unsupported untracked verification input: ${path}`);
    }
  }
  return { headCommit, workingStateHash: `sha256:${hash.digest("hex")}` };
}

/**
 * Host-neutral evaluation of one shell tool call. Claude `main()` and the OMP `tool_call`
 * adapter both call this. `toolName` is compared case-insensitively to `bash`.
 */
export function evaluateBashGuard({ toolName, command, cwd: inputCwd, env = process.env }) {
  if (String(toolName ?? "").toLowerCase() !== "bash") return { block: false };
  const terminalVerb = isTerminalGitCommand(command);
  if (!terminalVerb) return { block: false };

  const sessionCwd = inputCwd ?? process.cwd();
  const commandIsolated = isIsolatedTerminalGitCommand(command);
  const scopeRequiresSessionGuard = gitScopeRequiresSessionGuard(command);
  const cwd = resolveGitCwd(command, sessionCwd);
  const targetGuard = readJson(join(cwd, ".semctx", "guard.json"));
  const sessionGuard = scopeRequiresSessionGuard
    ? readJson(join(sessionCwd, ".semctx", "guard.json"))
    : null;
  const enabled = guardEnabled(env, targetGuard)
    || (scopeRequiresSessionGuard && guardEnabled(env, sessionGuard));
  if (!enabled) return { block: false };

  const state = commandIsolated
    ? readJson(join(cwd, ".semctx", "verification-state.json"))
    : null;
  let currentState = null;
  if (commandIsolated) {
    try {
      currentState = captureVerificationGitState(cwd);
    } catch {
      currentState = null;
    }
  }
  return guardDecision({
    enabled,
    terminalVerb,
    commandIsolated,
    state,
    currentState,
    verifyCommand: verifyRecordCommand(env),
  });
}

function main() {
  let input = {};
  try {
    input = JSON.parse(readFileSync(0, "utf8"));
  } catch {
    process.exit(0); // no/invalid input → do not block
  }
  const decision = evaluateBashGuard({
    toolName: input.tool_name ?? input.toolName,
    command: input.tool_input?.command ?? input.toolInput?.command ?? "",
    cwd: input.cwd ?? process.cwd(),
    env: process.env,
  });
  if (decision.block) {
    process.stderr.write(decision.reason + "\n");
    process.exit(2); // PreToolUse: non-zero (2) blocks the tool and surfaces stderr to the agent
  }
  process.exit(0);
}

if (process.argv[1]?.endsWith("semctx-guard.mjs")) main();
