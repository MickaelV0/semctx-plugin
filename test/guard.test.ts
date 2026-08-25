import { describe, it, expect } from "bun:test";
// The guard ships as runnable Node ESM (it runs on machines without Bun). bun:test imports it
// directly; main() is guarded by an argv check so importing does not execute it.
import {
  captureVerificationGitState,
  evaluateBashGuard,
  isIsolatedTerminalGitCommand,
  isTerminalGitCommand,
  guardEnabled,
  guardDecision,
  resolveGitCwd,
  verifyRecordCommand,
  shellQuote,
  GLOBAL_VERIFY_COMMAND,
} from "../hooks/semctx-guard.mjs";
import semctxGuard from "../hooks/pre/semctx-guard.ts";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { captureVerificationGitState as captureApplicationVerificationGitState } from "@semantic-context/app-services";

// A host-compatible POSIX shell is required only for shellQuote round-trip and command-replay e2e.
// Default Git-for-Windows puts Git\cmd on PATH (git.exe) but not Git\bin (bash.exe). Windows may
// also expose WSL's bash.exe, which cannot consume host paths or find the host Bun binary.
const hostPathProbe = process.platform === "win32" ? String.raw`C:\semctx probe\a$b` : "/tmp/semctx probe/a$b";
const quotedHostPathProbe = `'${hostPathProbe.replaceAll("'", "'\\''")}'`;
const hasHostCompatibleBash = (() => {
  try {
    const echoed = execFileSync("bash", ["-c", `printf '%s' ${quotedHostPathProbe}`], {
      encoding: "utf8",
    });
    return echoed === hostPathProbe;
  } catch {
    return false;
  }
})();
const bashCanRunBun =
  hasHostCompatibleBash &&
  (() => {
    try {
      execFileSync("bash", ["-c", "command -v bun >/dev/null"], { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  })();

describe("isTerminalGitCommand — structural detection (no shell eval)", () => {
  it("detects commit and push, including global options and env assignments", () => {
    expect(isTerminalGitCommand("git commit -m 'x'")).toBe("commit");
    expect(isTerminalGitCommand("git push origin main")).toBe("push");
    expect(isTerminalGitCommand("git -C sub commit -m x")).toBe("commit");
    expect(isTerminalGitCommand("git -c user.name=x commit")).toBe("commit");
    expect(isTerminalGitCommand("git --git-dir ../other/.git --work-tree ../other commit -m x")).toBe("commit");
    expect(isTerminalGitCommand("cd repo && git commit -m x")).toBe("commit");
    expect(isTerminalGitCommand("GIT_AUTHOR_NAME=x git commit")).toBe("commit");
    expect(isTerminalGitCommand("env GIT_DIR=../other/.git git commit -m x")).toBe("commit");
    expect(isTerminalGitCommand("env -i GIT_AUTHOR_NAME=x git commit -m x")).toBe("commit");
    expect(isTerminalGitCommand("env -u GIT_DIR git push origin main")).toBe("push");
    expect(isTerminalGitCommand("env -S 'git commit -m x'")).toBe("commit");
    expect(isTerminalGitCommand("git add -A && git commit -m x")).toBe("commit");
  });

  it("detects common wrapper, quoted, absolute-path, and shell -c shapes", () => {
    expect(isTerminalGitCommand("/usr/bin/git commit -m x")).toBe("commit");
    expect(isTerminalGitCommand('"git" push origin main')).toBe("push");
    expect(isTerminalGitCommand("command git commit -m x")).toBe("commit");
    expect(isTerminalGitCommand("bash -c 'git push origin main'")).toBe("push");
    expect(isTerminalGitCommand('powershell -Command "git commit -am x"')).toBe("commit");
    expect(isTerminalGitCommand('pwsh -Command "git push origin main"')).toBe("push");
    expect(isTerminalGitCommand('cmd /c "git commit -am x"')).toBe("commit");
    expect(isTerminalGitCommand('env bash -c "git push origin main"')).toBe("push");
    expect(isTerminalGitCommand('env -i bash --noprofile -c "git commit -am x"')).toBe("commit");
    expect(isTerminalGitCommand('pwsh -NoProfile -ExecutionPolicy Bypass -Command "git push origin main"')).toBe("push");
  });

  it("does not fire on non-terminal or look-alike commands", () => {
    expect(isTerminalGitCommand("git status")).toBeNull();
    expect(isTerminalGitCommand("git log --grep=commit")).toBeNull();
    expect(isTerminalGitCommand("git add -A")).toBeNull();
    expect(isTerminalGitCommand("echo git commit")).toBeNull();
    expect(isTerminalGitCommand("gitfoo commit")).toBeNull();
    expect(isTerminalGitCommand("npm run commit")).toBeNull();
    expect(isTerminalGitCommand("")).toBeNull();
  });
});

describe("isIsolatedTerminalGitCommand — no mutation before authorization", () => {
  it("allows one terminal Git operation with safe cwd, env, command, and Git prefixes", () => {
    expect(isIsolatedTerminalGitCommand("git commit -m x")).toBe(true);
    expect(isIsolatedTerminalGitCommand("cd repo && git push origin main")).toBe(true);
    expect(isIsolatedTerminalGitCommand("GIT_AUTHOR_NAME=x command git -C sub commit -m x")).toBe(true);
    expect(isIsolatedTerminalGitCommand("env GIT_AUTHOR_NAME=x git commit -m x")).toBe(true);
    expect(isIsolatedTerminalGitCommand("env -u SEMCTX_UNUSED git push origin main")).toBe(true);
  });

  it("rejects compound mutation, forced ignored staging, and shell substitutions", () => {
    expect(isIsolatedTerminalGitCommand("powershell -Command Set-Content tracked.ts bad && git commit -am x")).toBe(false);
    expect(isIsolatedTerminalGitCommand("git add -f ignored.txt && git commit -m x")).toBe(false);
    expect(isIsolatedTerminalGitCommand("git commit -m \"$(touch mutated.ts)\"")).toBe(false);
    expect(isIsolatedTerminalGitCommand("git commit -m x > commit.log")).toBe(false);
    expect(isIsolatedTerminalGitCommand('powershell -Command "git commit -am x"')).toBe(false);
    expect(isIsolatedTerminalGitCommand('pwsh -Command "git push origin main"')).toBe(false);
    expect(isIsolatedTerminalGitCommand('cmd /c "git commit -am x"')).toBe(false);
    expect(isIsolatedTerminalGitCommand('env bash -c "git commit -am x"')).toBe(false);
    expect(isIsolatedTerminalGitCommand('env -i bash --noprofile -c "git commit -am x"')).toBe(false);
    expect(isIsolatedTerminalGitCommand('pwsh -NoProfile -ExecutionPolicy Bypass -Command "git push origin main"')).toBe(false);
  });

  it("rejects cwd targets that require shell expansion", () => {
    for (const command of [
      "cd $SEMCTX_TARGET && git commit -m x",
      "cd ${SEMCTX_TARGET} && git push origin main",
      "cd ~ && git commit -m x",
      "git -C $SEMCTX_TARGET commit -m x",
      "git -C ${SEMCTX_TARGET} push origin main",
      "git -C ~ commit -m x",
      "git -C$SEMCTX_TARGET commit -m x",
    ]) {
      expect(isIsolatedTerminalGitCommand(command)).toBe(false);
    }
  });

  it("rejects environment, option, and config forms that retarget Git state", () => {
    for (const command of [
      "GIT_DIR=../other/.git git commit -m x",
      "GIT_WORK_TREE=../other git commit -m x",
      "GIT_COMMON_DIR=../other/.git git push origin main",
      "GIT_INDEX_FILE=../other/index git commit -m x",
      "GIT_CONFIG_COUNT=1 git commit -m x",
      "env GIT_DIR=../other/.git GIT_WORK_TREE=../other git commit -m x",
      "env -i GIT_COMMON_DIR=../other/.git git push origin main",
      "env -i GIT_AUTHOR_NAME=x git commit -m x",
      "env -u GIT_DIR git commit -m x",
      "env -C ../other git commit -m x",
      "env -S 'git commit -m x'",
      "git --git-dir ../other/.git --work-tree ../other commit -m x",
      "git --git-dir=../other/.git --work-tree=../other commit -m x",
      "git --namespace other push origin main",
      "git --bare commit -m x",
      "git -c core.worktree=../other commit -m x",
      "git -c core.bare=true commit -m x",
    ]) {
      expect(isIsolatedTerminalGitCommand(command)).toBe(false);
    }
  });
});

describe("guardEnabled — advisory by default, strict off wins", () => {
  it("defaults to advisory (false) with no env and no guard.json", () => {
    expect(guardEnabled({}, null)).toBe(false);
    expect(guardEnabled({}, { enabled: false })).toBe(false);
  });
  it("is guarded when .semctx/guard.json enables it", () => {
    expect(guardEnabled({}, { enabled: true })).toBe(true);
  });
  it("SEMCTX_GUARD=off strictly disables even if guard.json enables", () => {
    expect(guardEnabled({ SEMCTX_GUARD: "off" }, { enabled: true })).toBe(false);
  });
  it("SEMCTX_GUARD=on forces guarded", () => {
    expect(guardEnabled({ SEMCTX_GUARD: "on" }, null)).toBe(true);
  });
});

describe("guardDecision — diff-hash gate (ADR 0007)", () => {
  const HASH = "sha256:abc";
  const CURRENT = { headCommit: "a".repeat(40), workingStateHash: HASH };
  const STATE = { version: 2, ...CURRENT, verdict: "WARN" };
  it("advisory profile never blocks", () => {
    expect(guardDecision({ enabled: false, terminalVerb: "commit", state: null, currentState: CURRENT }).block).toBe(false);
  });
  it("non-terminal commands are never blocked", () => {
    expect(guardDecision({ enabled: true, terminalVerb: null, state: null, currentState: CURRENT }).block).toBe(false);
  });
  it("blocks a commit when no verification is on record", () => {
    const d = guardDecision({ enabled: true, terminalVerb: "commit", state: null, currentState: CURRENT });
    expect(d.block).toBe(true);
    expect(d.reason).toContain("verify diff --record");
  });

  it("emits a resolved, shell-quoted plugin CLI path — never a deferred shell variable", () => {
    // The reason string is executed by the agent's shell, which does NOT receive
    // CLAUDE_PLUGIN_ROOT (Claude Code exports it to hook and MCP processes only). A deferred
    // "$CLAUDE_PLUGIN_ROOT/…" would expand to "/dist/semctx.js".
    const missing = () => false;
    expect(verifyRecordCommand({}, missing)).toBe(GLOBAL_VERIFY_COMMAND);
    expect(verifyRecordCommand({ CLAUDE_PLUGIN_ROOT: "" }, missing)).toBe(GLOBAL_VERIFY_COMMAND);
    expect(verifyRecordCommand({ CLAUDE_PLUGIN_ROOT: "   " }, missing)).toBe(GLOBAL_VERIFY_COMMAND);

    const root = mkdtempSync(join(tmpdir(), "semctx-guard-plugin-root-"));
    try {
      mkdirSync(join(root, "dist"));
      writeFileSync(join(root, "dist", "semctx.js"), "// bundle\n");
      const command = verifyRecordCommand({ CLAUDE_PLUGIN_ROOT: root, PATH: process.env.PATH });
      expect(command).toBe(`bun '${join(root, "dist", "semctx.js")}' verify diff --record`);
      expect(command).not.toContain("$CLAUDE_PLUGIN_ROOT");

      const d = guardDecision({
        enabled: true,
        terminalVerb: "commit",
        state: null,
        currentState: CURRENT,
        verifyCommand: command,
      });
      expect(d.reason).toContain(command);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("shell-quotes roots containing spaces, quotes, and dollar signs", () => {
    for (const name of ["My Plugin", "it's", "a$b", "back`tick"]) {
      const parent = mkdtempSync(join(tmpdir(), "semctx-guard-odd-root-"));
      try {
        const root = join(parent, name);
        const bundle = join(root, "dist", "semctx.js");
        mkdirSync(join(root, "dist"), { recursive: true });
        writeFileSync(bundle, "// bundle\n");
        // Independent expected form (POSIX single-quote rule) — not shellQuote() itself, so a
        // degenerate identity transform would fail without needing bash.
        const expected = `bun '${bundle.replaceAll("'", "'\\''")}' verify diff --record`;
        expect(verifyRecordCommand({ CLAUDE_PLUGIN_ROOT: root, PATH: process.env.PATH })).toBe(expected);
      } finally {
        rmSync(parent, { recursive: true, force: true });
      }
    }
  });

  it.skipIf(!hasHostCompatibleBash)("shellQuote round-trips hostile paths through a real shell", () => {
    for (const name of ["My Plugin", "it's", "a$b", "back`tick"]) {
      const parent = mkdtempSync(join(tmpdir(), "semctx-guard-quote-roundtrip-"));
      try {
        const root = join(parent, name);
        const bundle = join(root, "dist", "semctx.js");
        mkdirSync(join(root, "dist"), { recursive: true });
        writeFileSync(bundle, "// bundle\n");
        const echoed = execFileSync("bash", ["-c", `printf '%s' ${shellQuote(bundle)}`], {
          encoding: "utf8",
        });
        expect(echoed).toBe(bundle);
      } finally {
        rmSync(parent, { recursive: true, force: true });
      }
    }
  });

  it("falls back to the global CLI when Bun is absent — the hook itself runs under Node", () => {
    const root = mkdtempSync(join(tmpdir(), "semctx-guard-nobun-"));
    try {
      mkdirSync(join(root, "dist"));
      writeFileSync(join(root, "dist", "semctx.js"), "// bundle\n");
      // Bundle present, but no `bun` anywhere on PATH.
      expect(verifyRecordCommand({ CLAUDE_PLUGIN_ROOT: root, PATH: join(root, "empty-bin") })).toBe(
        GLOBAL_VERIFY_COMMAND,
      );
      expect(verifyRecordCommand({ CLAUDE_PLUGIN_ROOT: root, PATH: "" })).toBe(GLOBAL_VERIFY_COMMAND);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("falls back to this hook's own bundle location when CLAUDE_PLUGIN_ROOT is absent", () => {
    // plugins/claude-code/hooks/../dist/semctx.js is a tracked artifact in this repo.
    expect(verifyRecordCommand({ PATH: process.env.PATH })).toBe(
      `bun '${resolve(import.meta.dir, "../dist/semctx.js")}' verify diff --record`,
    );
  });

  it("guardDecision is pure — no env read, no filesystem access", () => {
    const previous = process.env.CLAUDE_PLUGIN_ROOT;
    process.env.CLAUDE_PLUGIN_ROOT = "/plugins/should-not-be-read";
    try {
      const d = guardDecision({ enabled: true, terminalVerb: "commit", state: null, currentState: CURRENT });
      expect(d.reason).toContain(GLOBAL_VERIFY_COMMAND);
      expect(d.reason).not.toContain("should-not-be-read");
    } finally {
      if (previous === undefined) delete process.env.CLAUDE_PLUGIN_ROOT;
      else process.env.CLAUDE_PLUGIN_ROOT = previous;
    }
  });
  it("blocks a compound terminal command before consulting a valid baseline", () => {
    const d = guardDecision({
      enabled: true,
      terminalVerb: "commit",
      commandIsolated: false,
      state: STATE,
      currentState: CURRENT,
    });
    expect(d.block).toBe(true);
    expect(d.reason).toContain("must be an isolated command");
  });
  it("allows when the verified diff is unchanged and not BLOCK", () => {
    const d = guardDecision({ enabled: true, terminalVerb: "commit", state: STATE, currentState: CURRENT });
    expect(d.block).toBe(false);
  });
  it("blocks when the commit or working state changed since verification", () => {
    const d = guardDecision({
      enabled: true,
      terminalVerb: "push",
      state: { ...STATE, verdict: "PASS" },
      currentState: { ...CURRENT, workingStateHash: "sha256:changed" },
    });
    expect(d.block).toBe(true);
    expect(d.reason).toContain("changed since the last verification");
  });
  it("blocks when the recorded verdict was BLOCK, even if the diff is unchanged", () => {
    const d = guardDecision({ enabled: true, terminalVerb: "commit", state: { ...STATE, verdict: "BLOCK" }, currentState: CURRENT });
    expect(d.block).toBe(true);
    expect(d.reason).toContain("was BLOCK");
  });
  it("blocks legacy diff-only baselines", () => {
    const d = guardDecision({ enabled: true, terminalVerb: "commit", state: { diffHash: HASH, verdict: "PASS" }, currentState: CURRENT });
    expect(d.block).toBe(true);
    expect(d.reason).toContain("legacy");
  });
});

describe("guard runtime — large working diffs", () => {
  it("blocks a compound mutation command even with a matching baseline", () => {
    const repo = mkdtempSync(join(tmpdir(), "semctx-guard-compound-"));
    try {
      execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
      writeFileSync(join(repo, "tracked.ts"), "export const value = 1;\n");
      writeFileSync(join(repo, ".gitignore"), ".semctx/\nignored.txt\n");
      execFileSync("git", ["add", "tracked.ts", ".gitignore"], { cwd: repo, stdio: "ignore" });
      execFileSync(
        "git",
        ["-c", "user.name=Semctx Test", "-c", "user.email=semctx@example.invalid", "commit", "-m", "baseline"],
        { cwd: repo, stdio: "ignore" },
      );
      mkdirSync(join(repo, ".semctx"));
      writeFileSync(join(repo, ".semctx", "guard.json"), JSON.stringify({ enabled: true }));
      writeFileSync(
        join(repo, ".semctx", "verification-state.json"),
        JSON.stringify({ version: 2, ...captureVerificationGitState(repo), verdict: "PASS" }),
      );

      const guard = resolve(import.meta.dir, "../hooks/semctx-guard.mjs");
      const unsafeCommands = [
        "powershell -Command Set-Content tracked.ts bad && git commit -am x",
        'powershell -Command "git commit -am x"',
        'pwsh -Command "git push origin main"',
        'cmd /c "git commit -am x"',
        'env bash -c "git commit -am x"',
      ];
      for (const command of unsafeCommands) {
        const result = spawnSync("node", [guard], {
          cwd: repo,
          input: JSON.stringify({ tool_name: "Bash", tool_input: { command }, cwd: repo }),
          encoding: "utf8",
        });
        expect(result.status).toBe(2);
        expect(result.stderr).toContain("must be an isolated command");
      }
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it.skipIf(!bashCanRunBun)(
    "main() prints a verify command that a shell without CLAUDE_PLUGIN_ROOT can actually run",
    () => {
    const repo = mkdtempSync(join(tmpdir(), "semctx-guard-plugin-cli-"));
    const pluginParent = mkdtempSync(join(tmpdir(), "semctx-guard-plugin-home-"));
    // A space in the root is the realistic hostile case for quoting.
    const pluginRoot = join(pluginParent, "My Plugin");
    try {
      execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
      writeFileSync(join(repo, "tracked.ts"), "export const value = 1;\n");
      writeFileSync(join(repo, ".gitignore"), ".semctx/\n");
      execFileSync("git", ["add", "tracked.ts", ".gitignore"], { cwd: repo, stdio: "ignore" });
      execFileSync(
        "git",
        ["-c", "user.name=Semctx Test", "-c", "user.email=semctx@example.invalid", "commit", "-m", "baseline"],
        { cwd: repo, stdio: "ignore" },
      );
      mkdirSync(join(repo, ".semctx"));
      writeFileSync(join(repo, ".semctx", "guard.json"), JSON.stringify({ enabled: true }));
      mkdirSync(join(pluginRoot, "dist"), { recursive: true });
      writeFileSync(join(pluginRoot, "dist", "semctx.js"), 'process.stdout.write("bundle-ran");\n');

      // No verification-state.json → block with "Run: <verify command>"
      const guard = resolve(import.meta.dir, "../hooks/semctx-guard.mjs");
      const result = spawnSync("node", [guard], {
        cwd: repo,
        env: { ...process.env, CLAUDE_PLUGIN_ROOT: pluginRoot },
        input: JSON.stringify({
          tool_name: "Bash",
          tool_input: { command: "git commit -m x" },
          cwd: repo,
        }),
        encoding: "utf8",
      });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(join(pluginRoot, "dist", "semctx.js"));
      expect(result.stderr).not.toContain("$CLAUDE_PLUGIN_ROOT");

      // The decisive check: replay the printed command in a shell that has no CLAUDE_PLUGIN_ROOT,
      // exactly like the agent's Bash tool. A deferred "$CLAUDE_PLUGIN_ROOT/…" fails here.
      const printed = result.stderr
        .split("\n")
        .map((line) => line.trim())
        .find((line) => line.startsWith("bun "));
      expect(printed).toBeDefined();
      const { CLAUDE_PLUGIN_ROOT: _dropped, ...agentEnv } = process.env;
      const replay = spawnSync("bash", ["-c", printed!.replace(" verify diff --record", "")], {
        cwd: repo,
        env: agentEnv,
        encoding: "utf8",
      });
      expect(replay.status).toBe(0);
      expect(replay.stdout).toBe("bundle-ran");
    } finally {
      rmSync(repo, { recursive: true, force: true });
      rmSync(pluginParent, { recursive: true, force: true });
    }
  },
  );

  it("preserves the verification hash for a multi-megabyte diff", () => {
    const repo = mkdtempSync(join(tmpdir(), "semctx-guard-large-diff-"));
    try {
      execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
      writeFileSync(join(repo, "large.txt"), "a".repeat(2 * 1024 * 1024));
      writeFileSync(join(repo, ".gitignore"), ".semctx/\n");
      execFileSync("git", ["add", "large.txt", ".gitignore"], { cwd: repo, stdio: "ignore" });
      execFileSync(
        "git",
        ["-c", "user.name=Semctx Test", "-c", "user.email=semctx@example.invalid", "commit", "-m", "baseline"],
        { cwd: repo, stdio: "ignore" },
      );

      writeFileSync(join(repo, "large.txt"), "b".repeat(2 * 1024 * 1024));
      mkdirSync(join(repo, ".semctx"));
      writeFileSync(join(repo, ".semctx", "guard.json"), JSON.stringify({ enabled: true }));
      writeFileSync(
        join(repo, ".semctx", "verification-state.json"),
        JSON.stringify({ version: 2, ...captureVerificationGitState(repo), verdict: "PASS" }),
      );

      const guard = resolve(import.meta.dir, "../hooks/semctx-guard.mjs");
      const result = spawnSync("node", [guard], {
        cwd: repo,
        input: JSON.stringify({
          tool_name: "Bash",
          tool_input: { command: "git commit -m x" },
          cwd: repo,
        }),
        encoding: "utf8",
      });

      expect(result.status).toBe(0);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });
});

describe("guard runtime — repository scope must be explicit", () => {
  function createGuardedRepo(prefix: string) {
    const repo = mkdtempSync(join(tmpdir(), prefix));
    execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
    writeFileSync(join(repo, "tracked.ts"), "export const value = 1;\n");
    writeFileSync(join(repo, ".gitignore"), ".semctx/\n");
    execFileSync("git", ["add", "tracked.ts", ".gitignore"], { cwd: repo, stdio: "ignore" });
    execFileSync(
      "git",
      ["-c", "user.name=Semctx Test", "-c", "user.email=semctx@example.invalid", "commit", "-m", "baseline"],
      { cwd: repo, stdio: "ignore" },
    );
    mkdirSync(join(repo, ".semctx"));
    writeFileSync(join(repo, ".semctx", "guard.json"), JSON.stringify({ enabled: true }));
    writeFileSync(
      join(repo, ".semctx", "verification-state.json"),
      JSON.stringify({ version: 2, ...captureVerificationGitState(repo), verdict: "PASS" }),
    );
    return repo;
  }

  it("blocks unexpanded cd and git -C targets instead of losing the guarded session", () => {
    const repo = createGuardedRepo("semctx-guard-unexpanded-");
    try {
      const guard = resolve(import.meta.dir, "../hooks/semctx-guard.mjs");
      for (const command of [
        "cd $SEMCTX_TARGET && git commit -m x",
        "git -C $SEMCTX_TARGET push origin main",
        "git -C$SEMCTX_TARGET commit -m x",
      ]) {
        const result = spawnSync("node", [guard], {
          cwd: repo,
          env: { ...process.env, SEMCTX_TARGET: join(repo, "other") },
          input: JSON.stringify({ tool_name: "Bash", tool_input: { command }, cwd: repo }),
          encoding: "utf8",
        });
        expect(result.status).toBe(2);
        expect(result.stderr).toContain("must be an isolated command");
      }
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("blocks Git environment and CLI retargeting under a valid session baseline", () => {
    const repo = createGuardedRepo("semctx-guard-retarget-");
    try {
      const guard = resolve(import.meta.dir, "../hooks/semctx-guard.mjs");
      for (const command of [
        "GIT_DIR=../other/.git GIT_WORK_TREE=../other git commit -m x",
        "env GIT_DIR=../other/.git GIT_WORK_TREE=../other git commit -m x",
        "env -i GIT_COMMON_DIR=../other/.git git push origin main",
        "env -S 'git commit -m x'",
        "git --git-dir ../other/.git --work-tree ../other commit -m x",
      ]) {
        const result = spawnSync("node", [guard], {
          cwd: repo,
          input: JSON.stringify({ tool_name: "Bash", tool_input: { command }, cwd: repo }),
          encoding: "utf8",
        });
        expect(result.status).toBe(2);
        expect(result.stderr).toContain("must be an isolated command");
      }
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });
});

describe("verification-state capture parity", () => {
  it("matches the application service for tracked and untracked bytes", () => {
    const repo = mkdtempSync(join(tmpdir(), "semctx-guard-parity-"));
    try {
      execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
      writeFileSync(join(repo, "tracked.ts"), "export const value = 1;\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: repo, stdio: "ignore" });
      execFileSync(
        "git",
        ["-c", "user.name=Semctx Test", "-c", "user.email=semctx@example.invalid", "commit", "-m", "baseline"],
        { cwd: repo, stdio: "ignore" },
      );
      writeFileSync(join(repo, "tracked.ts"), "export const value = 2;\n");
      writeFileSync(join(repo, "untracked.ts"), "export const extra = true;\n");

      expect(captureVerificationGitState(repo)).toEqual(captureApplicationVerificationGitState(repo));
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });
});

describe("resolveGitCwd — evaluate the repo the command targets, not the session cwd", () => {
  const SESSION = resolve("/session/root");

  it("falls back to inputCwd for a plain git commit", () => {
    expect(resolveGitCwd("git commit -m x", SESSION)).toBe(SESSION);
  });

  it("honors git -C <relative>, resolved against inputCwd", () => {
    expect(resolveGitCwd("git -C sub commit -m x", SESSION)).toBe(resolve(SESSION, "sub"));
    expect(resolveGitCwd("git -Csub commit -m x", SESSION)).toBe(resolve(SESSION, "sub"));
  });

  it("honors a `cd <path> &&` prefix", () => {
    expect(resolveGitCwd("cd repo && git commit -m x", SESSION)).toBe(resolve(SESSION, "repo"));
  });

  it("accumulates chained cd, and applies -C on top of the running cd", () => {
    expect(resolveGitCwd("cd a && cd b && git commit", SESSION)).toBe(resolve(SESSION, "a", "b"));
    expect(resolveGitCwd("cd a && git -C c commit", SESSION)).toBe(resolve(SESSION, "a", "c"));
  });

  it("skips env assignments before git", () => {
    expect(resolveGitCwd("GIT_AUTHOR_NAME=x git -C sub commit", SESSION)).toBe(resolve(SESSION, "sub"));
    expect(resolveGitCwd("env -i GIT_AUTHOR_NAME=x git -C sub commit", SESSION)).toBe(resolve(SESSION, "sub"));
    expect(resolveGitCwd("env -u SEMCTX_UNUSED command git -C sub push", SESSION)).toBe(resolve(SESSION, "sub"));
  });

  it("honors -C when git is invoked through an absolute path or command wrapper", () => {
    expect(resolveGitCwd("/usr/bin/git -C sub commit", SESSION)).toBe(resolve(SESSION, "sub"));
    expect(resolveGitCwd("command git -C sub push", SESSION)).toBe(resolve(SESSION, "sub"));
  });

  it("resolves the same nested shell body used for terminal-command detection", () => {
    expect(resolveGitCwd("bash -c 'git -C ../other commit -m x'", SESSION)).toBe(resolve(SESSION, "../other"));
    expect(resolveGitCwd("sh -c 'cd nested && git push origin main'", SESSION)).toBe(resolve(SESSION, "nested"));
  });

  it("resolves an absolute -C path independently of inputCwd", () => {
    const abs = resolve("/other/repo");
    expect(resolveGitCwd(`git -C ${abs} commit`, SESSION)).toBe(abs);
  });

  it("regression: a git -C into another repo is NOT evaluated against the session repo", () => {
    // The cross-repo bug: `git -C <other> commit` from a guarded session must resolve to <other>,
    // whose (absent) guard.json makes it advisory — never the session repo's guard state.
    const other = resolve("/other/repo");
    expect(resolveGitCwd(`git -C ${other} commit -m x`, SESSION)).not.toBe(SESSION);
  });
});

function makeGuardedTestRepo(options: { enabled?: boolean } = {}) {
  const repo = mkdtempSync(join(tmpdir(), "semctx-guard-eval-"));
  execFileSync("git", ["init"], { cwd: repo, stdio: "ignore" });
  writeFileSync(join(repo, "tracked.ts"), "export const value = 1;\n");
  writeFileSync(join(repo, ".gitignore"), ".semctx/\n");
  execFileSync("git", ["add", "tracked.ts", ".gitignore"], { cwd: repo, stdio: "ignore" });
  execFileSync(
    "git",
    ["-c", "user.name=Semctx Test", "-c", "user.email=semctx@example.invalid", "commit", "-m", "baseline"],
    { cwd: repo, stdio: "ignore" },
  );
  if (options.enabled !== undefined) {
    mkdirSync(join(repo, ".semctx"));
    writeFileSync(join(repo, ".semctx", "guard.json"), JSON.stringify({ enabled: options.enabled }));
  }
  return repo;
}

describe("evaluateBashGuard — host-neutral shell tool gate", () => {
  it("non-bash tool names are never blocked", () => {
    const repo = makeGuardedTestRepo({ enabled: true });
    try {
      expect(evaluateBashGuard({ toolName: "read", command: "git commit -m x", cwd: repo }).block).toBe(false);
      expect(evaluateBashGuard({ toolName: "Write", command: "git commit -m x", cwd: repo }).block).toBe(false);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("bash and Bash block terminal git commit when guarded mode is enabled", () => {
    for (const toolName of ["bash", "Bash"]) {
      const repo = makeGuardedTestRepo({ enabled: true });
      try {
        const decision = evaluateBashGuard({ toolName, command: "git commit -m x", cwd: repo });
        expect(decision.block).toBe(true);
        expect(decision.reason).toContain("verify diff --record");
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    }
  });

  it("advisory default never blocks terminal git commit", () => {
    const repo = makeGuardedTestRepo();
    try {
      expect(evaluateBashGuard({ toolName: "bash", command: "git commit -m x", cwd: repo }).block).toBe(false);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }

    const advisoryRepo = makeGuardedTestRepo({ enabled: false });
    try {
      expect(evaluateBashGuard({ toolName: "bash", command: "git commit -m x", cwd: advisoryRepo }).block).toBe(
        false,
      );
    } finally {
      rmSync(advisoryRepo, { recursive: true, force: true });
    }
  });
});

describe("verifyRecordCommand — OMP plugin root", () => {
  it("resolves OMP_PLUGIN_ROOT the same as CLAUDE_PLUGIN_ROOT", () => {
    const root = mkdtempSync(join(tmpdir(), "semctx-guard-omp-plugin-root-"));
    try {
      mkdirSync(join(root, "dist"));
      writeFileSync(join(root, "dist", "semctx.js"), "// bundle\n");
      const expected = `bun '${join(root, "dist", "semctx.js")}' verify diff --record`;
      expect(verifyRecordCommand({ CLAUDE_PLUGIN_ROOT: root, PATH: process.env.PATH })).toBe(expected);
      expect(verifyRecordCommand({ OMP_PLUGIN_ROOT: root, PATH: process.env.PATH })).toBe(expected);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("semctxGuard — OMP tool_call adapter", () => {
  function installHandler() {
    let handler: (
      event: { toolName: string; input?: { command?: string; cwd?: string } },
      ctx: { cwd?: string },
    ) => Promise<unknown>;
    const pi = {
      on: (event: string, fn: typeof handler) => {
        if (event === "tool_call") handler = fn;
      },
    };
    semctxGuard(pi);
    return (event: Parameters<typeof handler>[0], ctx: Parameters<typeof handler>[1]) => handler(event, ctx);
  }

  it("blocks bash git commit when guarded and unverified", async () => {
    const repo = makeGuardedTestRepo({ enabled: true });
    try {
      const invoke = installHandler();
      const result = await invoke({ toolName: "bash", input: { command: "git commit -m x" } }, { cwd: repo });
      expect(result).toEqual(expect.objectContaining({ block: true }));
      expect((result as { reason: string }).reason).toContain("verify diff --record");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("does not block non-bash tools or non-terminal git commands", async () => {
    const repo = makeGuardedTestRepo({ enabled: true });
    try {
      const invoke = installHandler();
      expect(await invoke({ toolName: "read", input: { command: "git commit -m x" } }, { cwd: repo })).toBeUndefined();
      expect(await invoke({ toolName: "bash", input: { command: "git status" } }, { cwd: repo })).toBeUndefined();
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("swallows evaluator throws — OMP fail-closes on throw and would block every bash call", async () => {
    const invoke = installHandler();
    const event = new Proxy({}, { get() { throw new Error("boom"); } });
    await expect(invoke(event as never, {})).resolves.toBeUndefined();
  });

});
