/**
 * Approvers: how a person answers an approval request. Each must be a channel the model
 * cannot drive. None of them can stop an agent that also controls the screen (computer
 * use) or runs code as the same user; say so to anyone relying on them.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { stateDir } from "./changes.js";
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

/** Where the built presence helper is expected: INGRESS_PRESENCE_HELPER, or <state>/bin/ingress-presence. */
export function presenceHelperPath(): string { return process.env.INGRESS_PRESENCE_HELPER || join(stateDir(), "bin", "ingress-presence"); }

/**
 * An approval that also needs a person at the machine: after `inner` shows the exact action and is answered
 * "approve", macOS itself confirms someone is there (Touch ID, an unlocked Apple Watch, or the login password).
 * A dialog button can be clicked by anything that controls the pointer; a fingerprint cannot be produced by it.
 * Anything other than a confirmed person is a refusal: the helper missing, failing, or timing out included.
 *
 * Limits: with `biometryOnly: false` (the default) the login password is accepted, and an agent that knows
 * the password and controls the keyboard could type it. On a Mac with Touch ID, set `biometryOnly`.
 * A hardware security key (FIDO2) is not supported here.
 */
export function presenceApprover(inner: Approver, opts: { helper?: string; biometryOnly?: boolean } = {}): Approver {
  return {
    name: `${inner.name}+presence`,
    request: async (req: ApprovalRequest) => {
      const first = await inner.request(req);
      if (first !== "approved") return first;
      const helper = opts.helper ?? presenceHelperPath();
      // a helper in the state folder must be the one that was built here
      if (!opts.helper && !process.env.INGRESS_PRESENCE_HELPER) {
        try { if (readFileSync(`${helper}.sha256`, "utf8").trim() !== createHash("sha256").update(readFileSync(helper)).digest("hex")) return "denied"; } catch { return "denied"; }
      }
      const reason = `approve the action "${req.tool}" (${req.digest.slice(0, 12)})`;
      return new Promise((resolve) => {
        execFile(helper, [...(opts.biometryOnly ? ["--biometry-only"] : []), reason], { timeout: 150_000, encoding: "utf8" }, (err, stdout) => {
          if (err) return resolve(/nobody answered|timed out|ETIMEDOUT/i.test(`${stdout} ${err}`) ? "timeout" : "denied");
          try { resolve((JSON.parse(String(stdout)) as { ok?: boolean }).ok === true ? "approved" : "denied"); } catch { resolve("denied"); }
        });
      });
    },
  };
}

/** integrator-supplied channel (a console, a chat approval, a ticket) */
export function callbackApprover(name: string, fn: (req: ApprovalRequest) => Promise<"approved" | "denied" | "timeout">): Approver {
  return { name, request: fn };
}

/** no approval channel: everything that needs approval is refused (the safe default when nothing else is set up) */
export const denyAllApprover: Approver = { name: "none", request: async () => { throw new Error("no approver configured"); } };
