/**
 * Approvers: how a person answers an approval request. Each must be a channel the model
 * cannot drive. None of them can stop an agent that also controls the screen (computer
 * use) or runs code as the same user; say so to anyone relying on them.
 */

import { execFile } from "node:child_process";
import { describeApproval, type ApprovalRequest, type Approver } from "./broker.js";

/**
 * macOS: a native dialog showing the exact action, Deny as the default button, gives up
 * after `timeoutSec`. The text travels as an argument, never spliced into the script.
 */
export function macosDialogApprover(opts: { timeoutSec?: number; osascript?: string } = {}): Approver {
  const timeout = Math.max(10, Math.min(600, opts.timeoutSec ?? 120));
  const script = [
    "on run argv",
    "  set msg to item 1 of argv",
    `  set r to display dialog msg with title "AcePaste Ingress: approve this action?" buttons {"Deny", "Approve"} default button "Deny" cancel button "Deny" with icon caution giving up after ${timeout}`,
    "  if gave up of r then return \"timeout\"",
    "  if button returned of r is \"Approve\" then return \"approved\"",
    "  return \"denied\"",
    "end run",
  ].join("\n");
  return {
    name: "macos-dialog",
    request: (req: ApprovalRequest) => new Promise((resolve) => {
      execFile(opts.osascript ?? "/usr/bin/osascript", ["-e", script, describeApproval(req)], { timeout: (timeout + 15) * 1000 }, (err, stdout) => {
        const out = String(stdout ?? "").trim();
        if (out === "approved") return resolve("approved");
        if (out === "timeout") return resolve("timeout");
        // the Deny (cancel) button exits with an error; any failure is a refusal
        return resolve(err && /timed out|ETIMEDOUT/i.test(String(err)) ? "timeout" : "denied");
      });
    }),
  };
}

/** integrator-supplied channel (a console, a chat approval, a ticket) */
export function callbackApprover(name: string, fn: (req: ApprovalRequest) => Promise<"approved" | "denied" | "timeout">): Approver {
  return { name, request: fn };
}

/** no approval channel: everything that needs approval is refused (the safe default when nothing else is set up) */
export const denyAllApprover: Approver = { name: "none", request: async () => { throw new Error("no approver configured"); } };
