/**
 * Agentic Guardian (Thebe) — OpenClaw Hook Handler
 *
 * Place this file at:  ~/.openclaw/hooks/agentic-guardian/handler.ts
 * Place HOOK.md at:    ~/.openclaw/hooks/agentic-guardian/HOOK.md
 *
 * This handler intercepts every tool:call and agent:bootstrap event in
 * OpenClaw, submits the context to the Thebe Proxy, and enforces the
 * Guardian's verdict before the action is allowed to proceed.
 *
 * Environment Variables (set in ~/.openclaw/.env):
 *   THEBE_ENDPOINT             URL of the Thebe Proxy  (default: http://localhost:8000)
 *   THEBE_API_KEY              Vault key for proxy authentication
 *   THEBE_MIN_ALIGNMENT_SCORE  Float 0–1, minimum acceptable intent score (default: 0.85)
 *
 * Production note: the ThebeProxy class below is kept inline so that the
 * hook is fully self-contained.  Once the @delegant/thebe-sdk npm package
 * is published you can replace the class with:
 *
 *   import { ThebeProxy } from '@delegant/thebe-sdk';
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface OpenClawEvent {
  type: "tool:call" | "agent:bootstrap" | string;
  tool_name?: string;
  params?: Record<string, unknown>;
  session_id?: string;
  context?: {
    initial_prompt?: string;
    [key: string]: unknown;
  };
}

interface ThebePayload {
  userIntent: string;
  toolName: string;
  args: Record<string, unknown>;
  sessionId: string;
}

interface ThebeVerdict {
  decision: "ALLOW" | "DENY";
  reasoning_trace: string;
  requires_human_approval: boolean;
  alignment_score: number;
}

interface HookResult {
  block?: boolean;
  blockReason?: string;
  requireApproval?: boolean;
  approvalMessage?: string;
}

// ---------------------------------------------------------------------------
// ThebeProxy — lightweight SDK shim
// Replace with `import { ThebeProxy } from '@delegant/thebe-sdk'` once
// the package is published to npm.
// ---------------------------------------------------------------------------

class ThebeProxy {
  private readonly endpoint: string;
  private readonly apiKey: string;

  constructor(endpoint: string) {
    this.endpoint = endpoint.replace(/\/$/, "");
    this.apiKey = process.env.THEBE_API_KEY ?? "";
  }

  async validate(payload: ThebePayload): Promise<ThebeVerdict> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    // Only send the API key header when a key has been configured.
    if (this.apiKey) {
      headers["X-Thebe-Key"] = this.apiKey;
    }

    let response: Response;
    try {
      response = await fetch(`${this.endpoint}/validate`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
    } catch (networkError) {
      // If the proxy is unreachable, fail-open in dev or fail-closed in prod.
      const failOpen = (process.env.THEBE_FAIL_OPEN ?? "false") === "true";
      if (failOpen) {
        console.warn("[Thebe] Proxy unreachable — failing open (THEBE_FAIL_OPEN=true)");
        return {
          decision: "ALLOW",
          reasoning_trace: "Proxy unreachable; fail-open policy applied.",
          requires_human_approval: false,
          alignment_score: 0,
        };
      }
      throw new Error(
        `[Thebe] Cannot reach proxy at ${this.endpoint}: ${(networkError as Error).message}`
      );
    }

    if (!response.ok) {
      const body = await response.text().catch(() => "(no body)");
      throw new Error(`[Thebe] Proxy returned HTTP ${response.status}: ${body}`);
    }

    return (await response.json()) as ThebeVerdict;
  }
}

// ---------------------------------------------------------------------------
// Hook initialisation
// ---------------------------------------------------------------------------

const proxy = new ThebeProxy(
  process.env.THEBE_ENDPOINT ?? "http://localhost:8000"
);

// Minimum cosine-alignment score accepted by this hook layer.
// The proxy enforces its own threshold; this gives a second line of defence.
const MIN_SCORE = parseFloat(process.env.THEBE_MIN_ALIGNMENT_SCORE ?? "0.85");

// ---------------------------------------------------------------------------
// Main handler — called by OpenClaw for every intercepted event
// ---------------------------------------------------------------------------

export default async function guardianHandler(event: OpenClawEvent): Promise<HookResult | void> {
  // ── 1. Bootstrap guard ────────────────────────────────────────────────────
  // On agent:bootstrap, record the initial prompt so later tool:call handlers
  // always have the original user intention available.
  if (event.type === "agent:bootstrap") {
    console.info(
      `[Thebe] Agent session ${event.session_id ?? "unknown"} bootstrapped. ` +
        `Intent recorded: "${(event.context?.initial_prompt ?? "").slice(0, 80)}"`
    );
    // No blocking on bootstrap — this is purely observational.
    return;
  }

  // ── 2. Only process tool execution events ─────────────────────────────────
  if (event.type !== "tool:call") return;

  const toolName = event.tool_name ?? "unknown";
  const sessionId = event.session_id ?? "no-session";
  const userIntent = event.context?.initial_prompt ?? "";

  // ── 3. Build the payload for the Guardian ─────────────────────────────────
  const payload: ThebePayload = {
    userIntent,
    toolName,
    args: event.params ?? {},
    sessionId,
  };

  // ── 4. Request a verdict ──────────────────────────────────────────────────
  let verdict: ThebeVerdict;
  try {
    verdict = await proxy.validate(payload);
  } catch (err) {
    // Hard error from the proxy — block the action to preserve safety.
    const message = (err as Error).message;
    console.error(`[Thebe] Validation error for session ${sessionId}: ${message}`);
    return {
      block: true,
      blockReason: `🛡️ Agentic Guardian: validation failed — ${message}`,
    };
  }

  console.info(
    `[Thebe] session=${sessionId} tool=${toolName} ` +
      `decision=${verdict.decision} score=${verdict.alignment_score.toFixed(3)} ` +
      `human_approval=${verdict.requires_human_approval}`
  );

  // ── 5. Enforce the Shield ─────────────────────────────────────────────────
  if (verdict.decision === "DENY") {
    return {
      block: true,
      blockReason: `🛡️ Agentic Guardian: ${verdict.reasoning_trace}`,
    };
  }

  // Local alignment score check (second defence layer after the proxy).
  if (verdict.alignment_score > 0 && verdict.alignment_score < MIN_SCORE) {
    return {
      block: true,
      blockReason:
        `🛡️ Agentic Guardian: alignment score ${verdict.alignment_score.toFixed(3)} ` +
        `is below the required threshold of ${MIN_SCORE}.`,
    };
  }

  // ── 6. Proactive approval gate for high-risk actions ─────────────────────
  // (e.g. financial transactions, bulk deletions, email dispatch)
  if (verdict.requires_human_approval) {
    return {
      requireApproval: true,
      approvalMessage:
        `🛡️ Agentic Guardian has flagged "${toolName}" as a high-risk action ` +
        `(score: ${verdict.alignment_score.toFixed(3)}). ` +
        `Reasoning: ${verdict.reasoning_trace}. ` +
        `Do you authorise this operation?`,
    };
  }

  // ── 7. Allow the action to proceed ────────────────────────────────────────
  return { block: false };
}
