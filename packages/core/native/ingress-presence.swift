// ingress-presence: is a person at this machine, right now?
//
// An approval dialog can be clicked by anything that controls the pointer. This asks the operating system to
// confirm a person: Touch ID, an unlocked Apple Watch, or the login password, checked by macOS itself
// (LocalAuthentication). The answer is the system's, not this program's.
//
//   ingress-presence --check                      can this machine ask? prints JSON
//   ingress-presence [--biometry-only] <reason>   ask; exit 0 only if the person was confirmed
//
// Build: swiftc -O -swift-version 5 ingress-presence.swift -o ingress-presence   (macOS 12 or later)

import Foundation
import LocalAuthentication

func emit(_ d: [String: Any], _ code: Int32) -> Never {
  if let data = try? JSONSerialization.data(withJSONObject: d, options: [.sortedKeys]) { FileHandle.standardOutput.write(data); FileHandle.standardOutput.write("\n".data(using: .utf8)!) }
  exit(code)
}

var args = Array(CommandLine.arguments.dropFirst())
let biometryOnly = args.contains("--biometry-only")
args.removeAll { $0 == "--biometry-only" }
let policy: LAPolicy = biometryOnly ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
let ctx = LAContext()
var why: NSError?
let can = ctx.canEvaluatePolicy(policy, error: &why)
let kind: String = { switch ctx.biometryType { case .touchID: return "touch-id"; case .faceID: return "face-id"; default: return "none" } }()

if args.first == "--check" {
  emit(["available": can, "biometry": kind, "biometryOnly": biometryOnly, "reason": why?.localizedDescription ?? ""], 0)
}
guard let reason = args.first, !reason.isEmpty else {
  FileHandle.standardError.write("usage: ingress-presence --check | ingress-presence [--biometry-only] <reason>\n".data(using: .utf8)!)
  exit(2)
}
guard can else { emit(["ok": false, "error": why?.localizedDescription ?? "this machine cannot confirm a person"], 1) }

ctx.localizedCancelTitle = "Deny"
let done = DispatchSemaphore(value: 0)
var ok = false
var failure = ""
ctx.evaluatePolicy(policy, localizedReason: String(reason.prefix(300))) { success, error in
  ok = success
  failure = error?.localizedDescription ?? ""
  done.signal()
}
if done.wait(timeout: .now() + 120) == .timedOut { ctx.invalidate(); emit(["ok": false, "error": "nobody answered in two minutes"], 1) }
emit(ok ? ["ok": true, "biometry": kind] : ["ok": false, "error": failure], ok ? 0 : 1)
