import { evaluateBashGuard } from "../semctx-guard.mjs";

function sessionCwd(event, ctx) {
  if (typeof event?.input?.cwd === "string" && event.input.cwd) return event.input.cwd;
  if (typeof ctx?.cwd === "string" && ctx.cwd) return ctx.cwd;
  return process.cwd();
}

/** @param pi Oh My Pi extension API */
export default function semctxGuard(pi) {
  pi.on("tool_call", async (event, ctx) => {
    try {
      const command = typeof event?.input?.command === "string" ? event.input.command : "";
      const decision = evaluateBashGuard({
        toolName: event?.toolName,
        command,
        cwd: sessionCwd(event, ctx),
        env: process.env,
      });
      if (decision.block) {
        return { block: true, reason: decision.reason };
      }
    } catch {
      // OMP fail-closes on throw (blocks the tool). A guard bug must not block every bash call.
    }
  });
}
