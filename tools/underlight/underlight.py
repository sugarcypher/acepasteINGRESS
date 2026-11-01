#!/usr/bin/env python3
"""
underlight — inventory of JavaScript that can execute on this machine.

Working name; rename at will. Claude-generated, 2026-09-19. Unverified against
vendor reference hashes (self-baseline only in this version).

What it does
  1. runtimes        installed JavaScript interpreters on PATH and in common
                     install locations, plus engines EMBEDDED in application
                     binaries (Electron, Chromium Embedded Framework, Bun
                     single-file executables, V8/JavaScriptCore/QuickJS/Hermes
                     markers) — the Bun-as-malware-runtime pattern
  2. heap_images     V8 startup / context snapshot files, hashed, with a flag
                     for user-writable location — the CVE-2025-55305 precondition
  3. extensions      editor extensions (VS Code family, Cursor, Windsurf) and
                     Chromium-family browser extensions, with capability flags —
                     the Nx Console / GitHub breach pattern
  4. manifests       package.json files under your roots: URL-valued dependency
                     specifiers (PhantomRaven), lifecycle scripts in installed
                     packages with network/exec patterns (Axios / plain-crypto-js),
                     lockfile resolutions that point off-registry (declaration drift)

What it does NOT do
  - execute anything it finds (no `node --version`; hashes and sizes instead)
  - touch the network
  - phone home, log, or persist anything except the report you ask for

Every collector reports its own coverage: what it scanned, what it skipped,
whether it hit a cap. A clean report with a low coverage number is a low
coverage number, not a clean machine.

Usage
  python3 underlight.py scan                      # writes ./underlight-<ts>.json
  python3 underlight.py scan --out base.json      # save as your baseline
  python3 underlight.py scan --baseline base.json # scan, then diff against baseline
  python3 underlight.py diff base.json new.json   # diff two reports
  python3 underlight.py scan --roots ~/code ~/work --no-deep
  python3 underlight.py explain <path>            # what is this file, which package,
                                                  # who pulled it in, does it match the
                                                  # tarball in your local npm cache
  python3 underlight.py explain <path> --whole-package

Requires Python 3.9+. Standard library only.
"""

import argparse
import base64
import gzip
import hashlib
import io
import tarfile
import urllib.request
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "0.2.2"

# ----------------------------------------------------------------------------
# Limits — every walk is bounded. Change here, not inline.
# ----------------------------------------------------------------------------
MAX_BINARY_READ = 48 * 1024 * 1024      # bytes read per binary for marker scan
MAX_APP_WALK_FILES = 4000               # files visited per app bundle
MAX_APP_WALK_DEPTH = 9
MAX_MANIFEST_WALK_FILES = 60000         # filesystem entries visited across roots
MAX_MANIFEST_WALK_DEPTH = 8
MAX_NODE_MODULES_PER_PROJECT = 6000     # installed packages inspected per project
MAX_NODE_MODULES_TOTAL = 40000          # installed packages inspected across all projects
MAX_LOCKFILE_BYTES = 60 * 1024 * 1024
MAX_HASH_BYTES = 512 * 1024 * 1024      # refuse to hash anything larger
RECENT_DAYS = 90

SNAPSHOT_NAMES = {
    "v8_context_snapshot.bin",
    "v8_context_snapshot.arm64.bin",
    "v8_context_snapshot.x86_64.bin",
    "browser_v8_context_snapshot.bin",
    "browser_v8_context_snapshot.arm64.bin",
    "browser_v8_context_snapshot.x86_64.bin",
    "snapshot_blob.bin",
    "natives_blob.bin",
}

# Byte markers that indicate an embedded JavaScript engine. Heuristic by
# nature; each hit is reported with the marker that fired so you can judge it.
ENGINE_MARKERS = [
    (b"v8::internal::", "V8"),
    (b"V8 version", "V8"),
    (b"v8_context_snapshot", "V8"),
    (b"--js-flags", "V8"),
    (b"V8_CONTEXT_SNAPSHOT", "V8"),
    (b"/System/Library/Frameworks/JavaScriptCore.framework", "links-system-JavaScriptCore"),
    (b"JSGlobalContextCreate", "JavaScriptCore"),
    (b"JSC::VM", "JavaScriptCore"),
    (b"JS_NewContext", "QuickJS"),
    (b"quickjs-libc", "QuickJS"),
    (b"facebook::hermes", "Hermes"),
    (b"HermesRuntime", "Hermes"),
    (b"Bun.serve", "Bun"),
    (b"bun:main", "Bun"),
    (b"__BUN", "Bun-section"),
    (b".bun\x00", "Bun-section"),
    (b"Electron Framework", "Electron"),
    (b"electron/js2c", "Electron"),
    (b"Chromium Embedded Framework", "CEF"),
    (b"libcef", "CEF"),
    (b"node::Environment", "Node"),
    (b"NODE_OPTIONS", "Node"),
]

RUNTIME_NAMES = [
    "node", "nodejs", "bun", "deno", "qjs", "quickjs", "hermes", "hermesc",
    "jsc", "d8", "electron", "rhino", "graaljs", "js", "js115", "js128",
    "nw", "tsx", "ts-node",
]

LIFECYCLE_KEYS = ["preinstall", "install", "postinstall", "prepare",
                  "prepublish", "preprepare", "postprepare"]
# Scripts that run when the package is INSTALLED AS A DEPENDENCY (the ones that matter to a consumer).
# prepublish/prepublishOnly run only in the package's own checkout when its author publishes.
CONSUMER_LIFECYCLE = {"preinstall", "install", "postinstall", "prepare"}

SUSPICIOUS_SCRIPT_RE = re.compile(
    r"(curl\b|wget\b|fetch\(|https?://|child_process|\bexec\(|\bspawn\(|"
    r"node\s+-e\b|base64|\batob\(|\beval\(|\bFunction\(|powershell|/bin/sh|"
    r"bash\s+-c|\.sh\b|python[23]?\b|Invoke-WebRequest|certutil|"
    r"\$\{?HOME|~/\.ssh|\.npmrc|\.aws|\.config/gh|AWS_|GITHUB_TOKEN|NPM_TOKEN)",
    re.IGNORECASE,
)

URL_SPEC_RE = re.compile(
    r"^(https?://|git\+|git://|ssh://|github:|gitlab:|bitbucket:|gist:|"
    r"[\w.-]+/[\w.-]+(#.*)?$|.*\.tgz$|.*\.tar\.gz$)",
    re.IGNORECASE,
)

REGISTRY_HOSTS = {
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com",
    "registry.npmmirror.com",
}

BROAD_HOST_PERMS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
POWERFUL_PERMS = {"scripting", "webRequest", "webRequestBlocking",
                  "nativeMessaging", "debugger", "declarativeNetRequest",
                  "management", "proxy", "cookies", "tabs", "history",
                  "clipboardRead", "downloads"}

HOME = Path.home()
SYSTEM = platform.system()
VERBOSE = False


def progress(msg, end="\n"):
    """Always-flushed stderr progress. macOS line-buffers stderr on a tty."""
    sys.stderr.write(msg + end)
    sys.stderr.flush()


# ----------------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------------
class Coverage:
    """Per-collector accounting. Reported verbatim; never summarized away."""

    def __init__(self):
        self.visited = 0
        self.hashed = 0
        self.bytes_read = 0
        self.skipped_permission = 0
        self.skipped_size = 0
        self.skipped_other = 0
        self.cloud_only_skipped = 0
        self.capped = False
        self.cap_reason = None
        self.locations = []
        self.started = time.time()

    def finish(self):
        return {
            "visited": self.visited,
            "hashed": self.hashed,
            "bytes_read": self.bytes_read,
            "skipped_permission": self.skipped_permission,
            "skipped_size": self.skipped_size,
            "skipped_other": self.skipped_other,
            "cloud_only_skipped": self.cloud_only_skipped,
            "capped": self.capped,
            "cap_reason": self.cap_reason,
            "locations": self.locations,
            "elapsed_s": round(time.time() - self.started, 2),
        }


def sha256_file(path, cov):
    try:
        size = path.stat().st_size
        if size > MAX_HASH_BYTES:
            cov.skipped_size += 1
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        cov.hashed += 1
        cov.bytes_read += size
        return h.hexdigest()
    except PermissionError:
        cov.skipped_permission += 1
    except (OSError, ValueError):
        cov.skipped_other += 1
    return None


def file_meta(path, cov, want_hash=True):
    try:
        st = path.stat()
    except PermissionError:
        cov.skipped_permission += 1
        return None
    except OSError:
        cov.skipped_other += 1
        return None
    d = {
        "path": str(path),
        "size": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "user_writable": os.access(path, os.W_OK),
        "parent_user_writable": os.access(path.parent, os.W_OK),
    }
    if want_hash:
        d["sha256"] = sha256_file(path, cov)
    return d


def is_recent(iso, days=RECENT_DAYS):
    try:
        t = datetime.fromisoformat(iso)
        return (datetime.now(timezone.utc) - t).days < days
    except Exception:
        return False


def read_json(path, cov, max_bytes=8 * 1024 * 1024):
    try:
        if path.stat().st_size > max_bytes:
            cov.skipped_size += 1
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except PermissionError:
        cov.skipped_permission += 1
    except (OSError, ValueError):
        cov.skipped_other += 1
    return None


def scan_binary_markers(path, cov):
    """Read up to MAX_BINARY_READ bytes and look for engine markers."""
    found = {}
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            return found
        with open(path, "rb") as f:
            data = f.read(MAX_BINARY_READ)
        cov.bytes_read += len(data)
        cov.visited += 1
        for marker, engine in ENGINE_MARKERS:
            if marker in data:
                found.setdefault(engine, []).append(marker.decode("latin-1").strip("\x00"))
        if st.st_size > MAX_BINARY_READ:
            found["_truncated"] = True
    except PermissionError:
        cov.skipped_permission += 1
    except OSError:
        cov.skipped_other += 1
    return found


def bounded_walk(root, cov, max_files, max_depth, skip_names=(), follow_symlinks=False):
    """Yield (dirpath, dirnames, filenames) with caps. Sets cov.capped on limit."""
    root = Path(root)
    if not root.exists():
        return
    base_depth = len(root.parts)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks, onerror=lambda e: None):
        depth = len(Path(dirpath).parts) - base_depth
        dirnames[:] = [d for d in dirnames if d not in skip_names and not d.startswith(".Trash")]
        if depth >= max_depth:
            dirnames[:] = []
        count += len(filenames) + len(dirnames)
        cov.visited += len(filenames)
        cov.cloud_only_skipped += sum(1 for f in filenames if f.endswith(".icloud"))
        if count > max_files:
            cov.capped = True
            cov.cap_reason = f"{root}: exceeded {max_files} entries"
            return
        yield dirpath, dirnames, filenames


# ----------------------------------------------------------------------------
# Collector 1 — runtimes (installed + embedded)
# ----------------------------------------------------------------------------
def app_dirs():
    if SYSTEM == "Darwin":
        cands = [Path("/Applications"), HOME / "Applications",
                 Path("/Applications/Utilities"), Path("/opt/homebrew/Caskroom"),
                 Path("/usr/local/Caskroom")]
    elif SYSTEM == "Linux":
        cands = [Path("/opt"), Path("/usr/lib"), Path("/usr/local/lib"),
                 Path("/usr/share"), HOME / ".local/share", HOME / "Applications",
                 Path("/snap"), Path("/var/lib/flatpak/app"),
                 HOME / ".local/share/flatpak/app", HOME / "opt"]
    else:  # Windows best-effort
        la = os.environ.get("LOCALAPPDATA", "")
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        cands = [Path(la) / "Programs" if la else None, Path(pf), Path(pf86),
                 Path(la) if la else None]
    return [c for c in cands if c and c.exists()]


def collect_runtimes():
    cov = Coverage()
    installed = []
    embedded = []

    # --- installed interpreters on PATH and in known user-local locations
    seen = set()
    for name in RUNTIME_NAMES:
        p = shutil.which(name)
        if p:
            rp = Path(p).resolve()
            if rp not in seen:
                seen.add(rp)
                m = file_meta(rp, cov)
                if m:
                    m.update({"name": name, "source": "PATH", "invoked_as": p})
                    installed.append(m)

    extra_globs = [
        HOME / ".bun/bin/*", HOME / ".deno/bin/*", HOME / ".volta/bin/*",
        HOME / ".nvm/versions/node/*/bin/node", HOME / ".fnm/node-versions/*/installation/bin/node",
        HOME / ".local/share/fnm/node-versions/*/installation/bin/node",
        HOME / ".asdf/installs/nodejs/*/bin/node", HOME / ".n/bin/node",
        HOME / ".local/bin/*", Path("/opt/homebrew/bin/*"), Path("/usr/local/bin/*"),
        HOME / ".cargo/bin/*",
    ]
    for g in extra_globs:
        try:
            for p in Path(g.anchor).glob(str(g.relative_to(g.anchor))):
                if p.name in RUNTIME_NAMES and p.is_file():
                    rp = p.resolve()
                    if rp not in seen:
                        seen.add(rp)
                        m = file_meta(rp, cov)
                        if m:
                            m.update({"name": p.name, "source": "known-location", "invoked_as": str(p)})
                            installed.append(m)
        except (OSError, ValueError):
            cov.skipped_other += 1

    # --- embedded engines inside application bundles / install dirs
    progress(f"  {len(installed)} interpreters on PATH/known locations")
    n_apps = 0
    for base in app_dirs():
        cov.locations.append(str(base))
        try:
            entries = list(base.iterdir())
        except (PermissionError, OSError):
            cov.skipped_permission += 1
            continue
        progress(f"  scanning {base} ({len(entries)} entries) for embedded engines")
        for entry in entries:
            if SYSTEM == "Darwin":
                # Caskroom nests: Caskroom/<cask>/<ver>/<App>.app
                apps = [entry] if entry.suffix == ".app" else list(entry.glob("*.app")) + list(entry.glob("*/*.app"))
            else:
                apps = [entry]
            for app in apps[:50]:
                n_apps += 1
                if VERBOSE or n_apps % 25 == 0:
                    progress(f"    {n_apps} apps inspected, {len(embedded)} with embedded engines…")
                rec = inspect_app(app, cov)
                if rec:
                    embedded.append(rec)

    return {"installed": installed, "embedded": embedded, "coverage": cov.finish()}


def inspect_app(app, cov):
    """Return a record if the app embeds a JavaScript engine; else None."""
    rec = {"app": str(app), "frameworks": [], "markers": {}, "main_executable": None}
    try:
        if SYSTEM == "Darwin" and app.suffix == ".app":
            fw = app / "Contents" / "Frameworks"
            if (fw / "Electron Framework.framework").exists():
                rec["frameworks"].append("Electron Framework.framework")
            if (fw / "Chromium Embedded Framework.framework").exists():
                rec["frameworks"].append("Chromium Embedded Framework.framework")
            for f in fw.glob("*.framework") if fw.exists() else []:
                n = f.name
                if any(k in n for k in ("Electron", "Chromium", "JavaScriptCore", "Hermes", "V8", "node")):
                    if n not in rec["frameworks"]:
                        rec["frameworks"].append(n)
            info = app / "Contents" / "Info.plist"
            exe_name = None
            if info.exists():
                try:
                    with open(info, "rb") as f:
                        exe_name = plistlib.load(f).get("CFBundleExecutable")
                except Exception:
                    cov.skipped_other += 1
            exe = app / "Contents" / "MacOS" / exe_name if exe_name else None
            if exe and exe.exists():
                rec["main_executable"] = str(exe)
                rec["markers"] = scan_binary_markers(exe, cov)
            # Chromium/Electron apps keep the real engine in a framework binary,
            # not the stub in Contents/MacOS. Scan up to 6 framework binaries.
            rec["framework_binaries"] = []
            if fw.exists():
                n = 0
                for f in sorted(fw.glob("*.framework")):
                    stem = f.name[:-len(".framework")]
                    cands = [f / stem, f / "Versions" / "Current" / stem, f / "Versions" / "A" / stem]
                    cands += list((f / "Versions").glob("*/" + stem)) if (f / "Versions").exists() else []
                    for c in cands:
                        if c.is_file():
                            m = scan_binary_markers(c, cov)
                            if any(k != "_truncated" for k in m):
                                rec["framework_binaries"].append(str(c))
                                for k, v in m.items():
                                    if k == "_truncated":
                                        continue
                                    rec["markers"].setdefault(k, []).extend(v)
                            n += 1
                            break
                    if n >= 6:
                        break
            # Electron apps: also the framework binary itself carries V8
            efw = fw / "Electron Framework.framework" / "Electron Framework"
            if efw.exists() and "Electron" in rec["frameworks"][0:1] + rec["frameworks"]:
                rec["markers"].setdefault("Electron", []).append("framework-binary")
        else:
            # Linux/Windows: look for an obvious main binary + electron/bun indicators
            if app.is_file():
                rec["main_executable"] = str(app)
                rec["markers"] = scan_binary_markers(app, cov)
            elif app.is_dir():
                for cand in ("electron", app.name, app.name.lower(), f"{app.name}.exe"):
                    p = app / cand
                    if p.is_file():
                        rec["main_executable"] = str(p)
                        rec["markers"] = scan_binary_markers(p, cov)
                        break
                for n in ("libnode.so", "libffmpeg.so", "chrome_100_percent.pak", "resources.pak", "v8_context_snapshot.bin"):
                    if (app / n).exists():
                        rec["frameworks"].append(n)
    except (PermissionError, OSError):
        cov.skipped_permission += 1
        return None

    markers = {k: v for k, v in rec["markers"].items() if k != "_truncated"}
    rec["links_system_engine"] = [k.replace("links-system-", "") for k in markers if k.startswith("links-system-")]
    markers = {k: v for k, v in markers.items() if not k.startswith("links-system-")}
    if rec["frameworks"] or markers:
        rec["engines"] = sorted(set([("Bun" if k == "Bun-section" else k) for k in markers.keys()] +
                                    (["Electron"] if any("Electron" in f for f in rec["frameworks"]) else []) +
                                    (["CEF"] if any("Chromium" in f for f in rec["frameworks"]) else [])))
        return rec
    return None


# ----------------------------------------------------------------------------
# Collector 2 — heap images
# ----------------------------------------------------------------------------
def browser_install_dirs():
    if SYSTEM == "Darwin":
        return [Path("/Applications")]
    if SYSTEM == "Linux":
        return [Path("/opt"), Path("/usr/lib"), Path("/usr/lib64"), Path("/snap"),
                Path("/var/lib/flatpak/app"), HOME / ".local/share/flatpak/app"]
    la = os.environ.get("LOCALAPPDATA", "")
    return [p for p in [Path(la) if la else None,
                        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
                        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))] if p]


def collect_heap_images(extra_roots=()):
    cov = Coverage()
    images = []
    seen = set()
    roots = list(dict.fromkeys(app_dirs() + browser_install_dirs() + [Path(r) for r in extra_roots]))
    walk_units = []
    for root in roots:
        cov.locations.append(str(root))
        if SYSTEM == "Darwin" and root.name in ("Applications", "Utilities", "Caskroom"):
            # bound per app bundle rather than one global walk
            try:
                for entry in root.iterdir():
                    if entry.suffix == ".app":
                        if bundle_id(entry).startswith("com.apple."):
                            continue  # Apple bundles ship no V8 snapshots; saves the walk budget
                        walk_units.append((entry, MAX_APP_WALK_FILES * 3))
                    elif entry.is_dir():
                        for sub in list(entry.glob("*.app"))[:20] + list(entry.glob("*/*.app"))[:20]:
                            walk_units.append((sub, MAX_APP_WALK_FILES * 3))
            except (PermissionError, OSError):
                cov.skipped_permission += 1
        else:
            walk_units.append((root, MAX_APP_WALK_FILES * 60))
    progress(f"  {len(walk_units)} locations to walk for snapshots")
    for i, (unit, cap) in enumerate(walk_units, 1):
        if VERBOSE or i % 25 == 0:
            progress(f"    {i}/{len(walk_units)} walked, {len(images)} snapshots so far…")
        for dirpath, dirnames, filenames in bounded_walk(unit, cov, cap, MAX_APP_WALK_DEPTH + 4,
                                                          skip_names=("node_modules", ".git")):
            for fn in filenames:
                if fn in SNAPSHOT_NAMES:
                    p = Path(dirpath) / fn
                    rp = str(p.resolve()) if p.exists() else str(p)
                    if rp in seen:
                        continue
                    seen.add(rp)
                    m = file_meta(p, cov)
                    if m:
                        m["owning_app"] = owning_app(p)
                        images.append(m)
    return {"images": images, "coverage": cov.finish()}


def bundle_id(app):
    try:
        with open(app / "Contents" / "Info.plist", "rb") as f:
            return str(plistlib.load(f).get("CFBundleIdentifier", ""))
    except Exception:
        return ""


def owning_app(p):
    for parent in p.parents:
        if parent.suffix == ".app":
            return str(parent)
    parts = p.parts
    for i, part in enumerate(parts):
        if part in ("opt", "Applications", "Programs", "app") and i + 1 < len(parts):
            return str(Path(*parts[: i + 2]))
    return str(p.parent)


# ----------------------------------------------------------------------------
# Collector 3 — extensions (editor + browser)
# ----------------------------------------------------------------------------
EDITOR_EXT_DIRS = {
    "vscode": HOME / ".vscode/extensions",
    "vscode-insiders": HOME / ".vscode-insiders/extensions",
    "vscodium": HOME / ".vscode-oss/extensions",
    "cursor": HOME / ".cursor/extensions",
    "windsurf": HOME / ".windsurf/extensions",
    "positron": HOME / ".positron/extensions",
    "trae": HOME / ".trae/extensions",
}


def collect_editor_extensions():
    cov = Coverage()
    out = []
    for editor, d in EDITOR_EXT_DIRS.items():
        if not d.exists():
            continue
        cov.locations.append(str(d))
        try:
            entries = sorted(d.iterdir())
        except (PermissionError, OSError):
            cov.skipped_permission += 1
            continue
        for ext_dir in entries:
            if not ext_dir.is_dir():
                continue
            pj = ext_dir / "package.json"
            data = read_json(pj, cov)
            if not isinstance(data, dict):
                continue
            cov.visited += 1
            main_rel = data.get("main") or data.get("browser")
            main_path = (ext_dir / main_rel) if main_rel else None
            main_meta = file_meta(main_path, cov) if main_path and main_path.exists() else None
            activation = data.get("activationEvents") or []
            contributes = data.get("contributes") or {}
            try:
                dir_mtime = datetime.fromtimestamp(ext_dir.stat().st_mtime, tz=timezone.utc).isoformat()
            except OSError:
                dir_mtime = None
            rec = {
                "editor": editor,
                "dir": str(ext_dir),
                "id": f"{data.get('publisher', '?')}.{data.get('name', ext_dir.name)}",
                "publisher": data.get("publisher"),
                "name": data.get("name"),
                "version": data.get("version"),
                "display_name": data.get("displayName"),
                "main": main_rel,
                "main_sha256": (main_meta or {}).get("sha256"),
                "main_size": (main_meta or {}).get("size"),
                "package_json_sha256": sha256_file(pj, cov),
                "dir_mtime": dir_mtime,
                "activation_events": activation,
                "activates_always": ("*" in activation) or ("onStartupFinished" in activation),
                "contributes_keys": sorted(contributes.keys()) if isinstance(contributes, dict) else [],
                "extension_dependencies": data.get("extensionDependencies") or [],
                "has_node_modules": (ext_dir / "node_modules").exists(),
                "recent": is_recent(dir_mtime) if dir_mtime else False,
            }
            out.append(rec)
    return {"extensions": out, "coverage": cov.finish()}


def browser_profile_roots():
    if SYSTEM == "Darwin":
        base = HOME / "Library/Application Support"
        cands = {
            "brave": base / "BraveSoftware/Brave-Browser",
            "chrome": base / "Google/Chrome",
            "chrome-beta": base / "Google/Chrome Beta",
            "chrome-canary": base / "Google/Chrome Canary",
            "chromium": base / "Chromium",
            "edge": base / "Microsoft Edge",
            "arc": base / "Arc/User Data",
            "vivaldi": base / "Vivaldi",
            "opera": base / "com.operasoftware.Opera",
        }
    elif SYSTEM == "Linux":
        base = HOME / ".config"
        cands = {
            "brave": base / "BraveSoftware/Brave-Browser",
            "chrome": base / "google-chrome",
            "chromium": base / "chromium",
            "edge": base / "microsoft-edge",
            "vivaldi": base / "vivaldi",
        }
    else:
        la = Path(os.environ.get("LOCALAPPDATA", "C:/Users/Public"))
        cands = {
            "brave": la / "BraveSoftware/Brave-Browser/User Data",
            "chrome": la / "Google/Chrome/User Data",
            "edge": la / "Microsoft/Edge/User Data",
            "chromium": la / "Chromium/User Data",
        }
    return {k: v for k, v in cands.items() if v.exists()}


def resolve_msg(value, ext_ver_dir, data, cov):
    """Resolve __MSG_key__ names via _locales if cheap."""
    if not (isinstance(value, str) and value.startswith("__MSG_") and value.endswith("__")):
        return value
    key = value[6:-2]
    loc = data.get("default_locale", "en")
    for cand in (loc, "en", "en_US"):
        mp = ext_ver_dir / "_locales" / cand / "messages.json"
        if mp.exists():
            msgs = read_json(mp, cov, max_bytes=2 * 1024 * 1024)
            if isinstance(msgs, dict) and key in msgs and isinstance(msgs[key], dict):
                return msgs[key].get("message", value)
    return value


def collect_browser_extensions():
    cov = Coverage()
    out = []
    for browser, root in browser_profile_roots().items():
        cov.locations.append(str(root))
        try:
            profiles = [p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]
        except (PermissionError, OSError):
            cov.skipped_permission += 1
            continue
        for prof in profiles:
            ext_root = prof / "Extensions"
            if not ext_root.exists():
                continue
            try:
                ids = list(ext_root.iterdir())
            except (PermissionError, OSError):
                cov.skipped_permission += 1
                continue
            for ext_id in ids:
                if not ext_id.is_dir():
                    continue
                try:
                    versions = [v for v in ext_id.iterdir() if v.is_dir()]
                except (PermissionError, OSError):
                    cov.skipped_permission += 1
                    continue
                for vdir in versions:
                    mf = vdir / "manifest.json"
                    data = read_json(mf, cov)
                    if not isinstance(data, dict):
                        continue
                    cov.visited += 1
                    perms = set(data.get("permissions") or []) | set(data.get("optional_permissions") or [])
                    hosts = set(data.get("host_permissions") or []) | {p for p in perms if "://" in p or p == "<all_urls>"}
                    perms = {p for p in perms if not ("://" in p or p == "<all_urls>")}
                    cs = data.get("content_scripts") or []
                    cs_matches = set()
                    for c in cs:
                        cs_matches |= set(c.get("matches") or [])
                    bg = data.get("background") or {}
                    try:
                        vm = datetime.fromtimestamp(vdir.stat().st_mtime, tz=timezone.utc).isoformat()
                    except OSError:
                        vm = None
                    out.append({
                        "browser": browser,
                        "profile": prof.name,
                        "id": ext_id.name,
                        "version": data.get("version"),
                        "name": resolve_msg(data.get("name"), vdir, data, cov),
                        "manifest_version": data.get("manifest_version"),
                        "dir": str(vdir),
                        "dir_mtime": vm,
                        "recent": is_recent(vm) if vm else False,
                        "permissions": sorted(perms),
                        "host_permissions": sorted(hosts),
                        "content_script_matches": sorted(cs_matches),
                        "content_script_count": len(cs),
                        "background": bool(bg),
                        "broad_host_access": bool((hosts | cs_matches) & BROAD_HOST_PERMS),
                        "powerful_permissions": sorted(perms & POWERFUL_PERMS),
                        "manifest_sha256": sha256_file(mf, cov),
                        "update_url": data.get("update_url"),
                        "unpacked_or_sideloaded": not bool(data.get("update_url")),
                    })
    return {"extensions": out, "coverage": cov.finish()}


# ----------------------------------------------------------------------------
# Collector 4 — manifests, installed lifecycle scripts, lockfile resolutions
# ----------------------------------------------------------------------------
MANIFEST_SKIP = {
    "node_modules", ".git", ".hg", ".svn", "Library", ".Trash", ".cache", ".npm",
    ".cargo", ".rustup", ".pnpm-store", "Applications", "Pictures", "Movies",
    "Music", "snap", "__pycache__", ".venv", "venv", ".gradle", ".m2", ".docker",
    ".ollama", "go", ".local", ".config", "Photos Library.photoslibrary",
    ".Spotlight-V100", ".DocumentRevisions-V100", ".fseventsd", ".Xcode",
    "DerivedData", "Caches", "Google Drive", "iCloud Drive", "OneDrive", "Dropbox",
    ".vscode", ".vscode-insiders", ".vscode-oss", ".cursor", ".windsurf", ".positron", ".trae",
}


def lifecycle_from(data):
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return {}
    out = {}
    for k in LIFECYCLE_KEYS:
        v = scripts.get(k)
        if isinstance(v, str) and v.strip():
            out[k] = {"script": v[:600], "suspicious": bool(SUSPICIOUS_SCRIPT_RE.search(v))}
    return out


def url_deps_from(data):
    out = []
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies"):
        deps = data.get(field)
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if isinstance(spec, str) and URL_SPEC_RE.match(spec.strip()):
                    out.append({"field": field, "name": name, "spec": spec})
    return out


def host_of(url):
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/@]+@)?([^/:]+)", url, re.IGNORECASE)
    return m.group(2).lower() if m else None


def scan_lockfiles(project_dir, cov):
    """Return resolved URLs whose host is not a known public registry."""
    off = []
    seen_hosts = {}
    # package-lock.json / npm-shrinkwrap.json
    for name in ("package-lock.json", "npm-shrinkwrap.json"):
        lf = project_dir / name
        if lf.exists():
            data = read_json(lf, cov, max_bytes=MAX_LOCKFILE_BYTES)
            if isinstance(data, dict):
                pkgs = data.get("packages") or {}
                deps = data.get("dependencies") or {}
                for key, v in list(pkgs.items()) + list(deps.items()):
                    if isinstance(v, dict) and isinstance(v.get("resolved"), str):
                        h = host_of(v["resolved"])
                        if h and h not in REGISTRY_HOSTS:
                            seen_hosts[h] = seen_hosts.get(h, 0) + 1
                            if len(off) < 200:
                                off.append({"lockfile": name, "package": key, "resolved": v["resolved"][:300]})
    # yarn.lock
    yl = project_dir / "yarn.lock"
    if yl.exists():
        try:
            if yl.stat().st_size <= MAX_LOCKFILE_BYTES:
                with open(yl, "r", encoding="utf-8", errors="replace") as f:
                    txt = f.read()
                cov.bytes_read += len(txt)
                for m in re.finditer(r'resolved\s+"?([^"\s]+)', txt):
                    h = host_of(m.group(1))
                    if h and h not in REGISTRY_HOSTS:
                        seen_hosts[h] = seen_hosts.get(h, 0) + 1
                        if len(off) < 200:
                            off.append({"lockfile": "yarn.lock", "package": None, "resolved": m.group(1)[:300]})
            else:
                cov.skipped_size += 1
        except (PermissionError, OSError):
            cov.skipped_permission += 1
    # pnpm-lock.yaml
    pl = project_dir / "pnpm-lock.yaml"
    if pl.exists():
        try:
            if pl.stat().st_size <= MAX_LOCKFILE_BYTES:
                with open(pl, "r", encoding="utf-8", errors="replace") as f:
                    txt = f.read()
                cov.bytes_read += len(txt)
                for m in re.finditer(r"(?:tarball|resolution|integrity)?[:\s]\s*'?\"?(https?://[^\s'\"}]+)", txt):
                    h = host_of(m.group(1))
                    if h and h not in REGISTRY_HOSTS:
                        seen_hosts[h] = seen_hosts.get(h, 0) + 1
                        if len(off) < 200:
                            off.append({"lockfile": "pnpm-lock.yaml", "package": None, "resolved": m.group(1)[:300]})
            else:
                cov.skipped_size += 1
        except (PermissionError, OSError):
            cov.skipped_permission += 1
    return off, seen_hosts


_NM_TOTAL = {"n": 0}


def scan_node_modules(project_dir, direct_names, cov):
    nm = project_dir / "node_modules"
    if not nm.exists():
        return [], 0
    if _NM_TOTAL["n"] >= MAX_NODE_MODULES_TOTAL:
        cov.capped = True
        cov.cap_reason = f"global cap of {MAX_NODE_MODULES_TOTAL} installed packages reached before {nm}"
        return [], 0
    findings = []
    count = 0
    try:
        tops = list(nm.iterdir())
    except (PermissionError, OSError):
        cov.skipped_permission += 1
        return [], 0
    pkg_dirs = []
    for t in tops:
        if t.name.startswith("@") and t.is_dir():
            try:
                pkg_dirs.extend([s for s in t.iterdir() if s.is_dir()])
            except (PermissionError, OSError):
                cov.skipped_permission += 1
        elif t.is_dir() and not t.name.startswith("."):
            pkg_dirs.append(t)
    for pd in pkg_dirs:
        count += 1
        _NM_TOTAL["n"] += 1
        if _NM_TOTAL["n"] % 2000 == 0:
            progress(f"    {_NM_TOTAL['n']} installed packages inspected so far… ({nm})")
        if count > MAX_NODE_MODULES_PER_PROJECT:
            cov.capped = True
            cov.cap_reason = f"{nm}: exceeded {MAX_NODE_MODULES_PER_PROJECT} packages"
            break
        if _NM_TOTAL["n"] > MAX_NODE_MODULES_TOTAL:
            cov.capped = True
            cov.cap_reason = f"global cap of {MAX_NODE_MODULES_TOTAL} installed packages reached at {nm}"
            break
        pj = pd / "package.json"
        data = read_json(pj, cov, max_bytes=2 * 1024 * 1024)
        if not isinstance(data, dict):
            continue
        cov.visited += 1
        lc = lifecycle_from(data)
        ud = url_deps_from(data)
        if lc or ud:
            name = data.get("name") or pd.name
            findings.append({
                "package": name,
                "version": data.get("version"),
                "dir": str(pd),
                "direct": name in direct_names,
                "lifecycle": lc,
                "url_deps": ud,
                "has_binding_gyp": (pd / "binding.gyp").exists(),
            })
    return findings, count


ICLOUD_DRIVE = HOME / "Library/Mobile Documents/com~apple~CloudDocs"


def collect_manifests(roots, deep=True):
    cov = Coverage()
    projects = []
    roots = list(roots)
    if SYSTEM == "Darwin" and ICLOUD_DRIVE.exists() and not any(Path(r).expanduser() == ICLOUD_DRIVE for r in roots):
        roots.append(str(ICLOUD_DRIVE))  # ~/Library is skipped by name; iCloud Drive lives inside it
    for root in roots:
        root = Path(root).expanduser()
        if not root.exists():
            continue
        cov.locations.append(str(root))
        for dirpath, dirnames, filenames in bounded_walk(root, cov, MAX_MANIFEST_WALK_FILES,
                                                          MAX_MANIFEST_WALK_DEPTH, skip_names=MANIFEST_SKIP):
            if "package.json" not in filenames:
                continue
            pdir = Path(dirpath)
            pj = pdir / "package.json"
            data = read_json(pj, cov)
            if not isinstance(data, dict):
                continue
            direct = set()
            for field in ("dependencies", "devDependencies", "optionalDependencies"):
                d = data.get(field)
                if isinstance(d, dict):
                    direct |= set(d.keys())
            proj = {
                "dir": str(pdir),
                "name": data.get("name"),
                "version": data.get("version"),
                "private": bool(data.get("private")),
                "direct_dependency_count": len(direct),
                "url_deps": url_deps_from(data),
                "lifecycle": lifecycle_from(data),
                "installed": [],
                "installed_count": 0,
                "off_registry": [],
                "off_registry_hosts": {},
            }
            proj["off_registry"], proj["off_registry_hosts"] = scan_lockfiles(pdir, cov)
            if deep:
                proj["installed"], proj["installed_count"] = scan_node_modules(pdir, direct, cov)
            projects.append(proj)
            if VERBOSE or len(projects) % 20 == 0:
                progress(f"    {len(projects)} projects, {cov.visited} entries visited… ({pdir})")
            # do not descend into this project's node_modules via the outer walk
            dirnames[:] = [d for d in dirnames if d != "node_modules"]
    return {"projects": projects, "coverage": cov.finish()}


# ----------------------------------------------------------------------------
# Findings — derived, severity-tagged, each pointing at one record
# ----------------------------------------------------------------------------
def derive_findings(report):
    F = []

    def add(sev, kind, subject, detail):
        F.append({"severity": sev, "kind": kind, "subject": subject, "detail": detail})

    # runtimes
    for e in report["runtimes"]["embedded"]:
        eng = e.get("engines", [])
        if "Bun" in eng or "Bun-section" in eng:
            fw = e.get("frameworks", [])
            if not any("Bun" in f for f in fw):
                add("medium", "embedded-bun-runtime", e["app"],
                    "Application binary carries Bun runtime markers. Bun has been used as a malware delivery "
                    "runtime because endpoint tooling is tuned to node.exe (Malwarebytes, May 2026). Verify the "
                    "publisher expects Bun here.")
        if e.get("markers", {}).get("_truncated"):
            add("note", "binary-scan-truncated", e["app"],
                f"Only the first {MAX_BINARY_READ // (1024 * 1024)} MB were scanned for engine markers.")
    for r in report["runtimes"]["installed"]:
        if r.get("source") == "known-location" and r.get("user_writable"):
            add("note", "user-writable-interpreter", r["path"],
                "Interpreter binary is writable by the current user; replaceable without elevation.")

    # heap images
    for img in report["heap_images"]["images"]:
        if img.get("user_writable") or img.get("parent_user_writable"):
            add("note", "heap-image-user-writable", img["path"],
                "V8 snapshot is modifiable without privilege elevation — the precondition for CVE-2025-55305 "
                "(built-in clobbering that survives code-signature checks). Normal on macOS/Windows defaults; "
                "the diff against your baseline is what turns this into a finding.")
        if img.get("sha256") is None:
            add("note", "heap-image-unhashed", img["path"], "Could not hash (permission or size).")

    # editor extensions
    for x in report["editor_extensions"]["extensions"]:
        if x.get("activates_always"):
            add("note", "extension-activates-always", f"{x['editor']}:{x['id']}",
                "Activates on every editor start regardless of workspace.")
        if x.get("recent"):
            add("note", "extension-recently-modified", f"{x['editor']}:{x['id']}",
                f"Extension directory modified within {RECENT_DAYS} days (version {x.get('version')}).")
        if not x.get("publisher"):
            add("low", "extension-no-publisher", f"{x['editor']}:{x['id']}", "No publisher field in package.json.")
        if x.get("main") and not x.get("main_sha256"):
            add("low", "extension-main-missing", f"{x['editor']}:{x['id']}",
                f"Declared main '{x['main']}' not found or unreadable.")

    # browser extensions — one finding per (browser, profile, id); newest version wins
    latest = {}
    for x in report["browser_extensions"]["extensions"]:
        k = (x["browser"], x["profile"], x["id"])
        if k not in latest or str(x.get("version")) > str(latest[k].get("version")):
            latest[k] = x
    for x in latest.values():
        subj = f"{x['browser']}/{x['profile']}:{x['id']} ({x.get('name')})"
        if x.get("broad_host_access") and x.get("powerful_permissions"):
            add("low", "browser-extension-broad-and-powerful", subj,
                f"All-sites access plus {', '.join(x['powerful_permissions'])}. A capability, not an indicator; "
                "review whether the extension's function needs it.")
        elif x.get("broad_host_access"):
            add("note", "browser-extension-broad-host", subj, "All-sites host access.")
        if x.get("unpacked_or_sideloaded"):
            add("low", "browser-extension-sideloaded", subj,
                "No update_url in manifest — unpacked or sideloaded rather than store-installed.")

    # manifests
    for p in report["manifests"]["projects"]:
        for ud in p["url_deps"]:
            add("high", "url-valued-dependency", f"{p['dir']} :: {ud['name']}",
                f"{ud['field']} specifier '{ud['spec']}' resolves to a network location, not a registry. "
                "Registry scanners see zero dependencies (PhantomRaven pattern). The remote host can serve "
                "different content to different requesters.")
        for k, v in p["lifecycle"].items():
            if v["suspicious"]:
                add("medium", "project-lifecycle-suspicious", f"{p['dir']} :: scripts.{k}",
                    f"Lifecycle script matches network/exec/credential pattern: {v['script'][:160]}")
        if p["off_registry"]:
            hosts = ", ".join(f"{h} ({n})" for h, n in sorted(p["off_registry_hosts"].items(), key=lambda t: -t[1])[:6])
            add("medium", "lockfile-off-registry", p["dir"],
                f"{len(p['off_registry'])}+ resolutions point off public registries: {hosts}. Legitimate for a "
                "private registry or git dependency; otherwise this is declaration drift.")
        for inst in p["installed"]:
            subj = f"{p['dir']} :: node_modules/{inst['package']}@{inst.get('version')}"
            for k, v in inst["lifecycle"].items():
                if v["suspicious"]:
                    sev = "high" if not inst["direct"] else "medium"
                    add(sev, "installed-lifecycle-suspicious", subj,
                        f"{'Transitive' if not inst['direct'] else 'Direct'} dependency runs a {k} script matching "
                        f"network/exec/credential pattern: {v['script'][:160]}")
                elif not inst["direct"]:
                    add("note", "installed-lifecycle-transitive", subj,
                        f"Transitive dependency declares a {k} script (no suspicious pattern matched).")
            for ud in inst["url_deps"]:
                add("high", "installed-url-valued-dependency", subj,
                    f"Installed package declares {ud['field']} '{ud['name']}' = '{ud['spec']}'.")

    order = {"high": 0, "medium": 1, "low": 2, "note": 3}
    F.sort(key=lambda f: (order[f["severity"]], f["kind"], f["subject"]))
    return F


# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
def summarize(report):
    rt = report["runtimes"]
    hi = report["heap_images"]["images"]
    ee = report["editor_extensions"]["extensions"]
    be = report["browser_extensions"]["extensions"]
    pr = report["manifests"]["projects"]
    installed_lc = sum(1 for p in pr for i in p["installed"] if i["lifecycle"])
    installed_lc_susp = sum(1 for p in pr for i in p["installed"] for v in i["lifecycle"].values() if v["suspicious"])
    installed_lc_trans = sum(1 for p in pr for i in p["installed"] if i["lifecycle"] and not i["direct"])
    s = {
        "runtimes_installed": len(rt["installed"]),
        "runtimes_embedded_apps": len(rt["embedded"]),
        "runtimes_embedded_engines": sorted({e for a in rt["embedded"] for e in a.get("engines", [])}),
        "runtimes_links_system_engine": sum(1 for a in rt["embedded"] if a.get("links_system_engine")),
        "heap_images": len(hi),
        "heap_images_user_writable": sum(1 for i in hi if i.get("user_writable") or i.get("parent_user_writable")),
        "editor_extensions": len(ee),
        "editor_extensions_activate_always": sum(1 for x in ee if x.get("activates_always")),
        "editor_extensions_recent": sum(1 for x in ee if x.get("recent")),
        "browser_extensions": len(be),
        "browser_extensions_broad_host": sum(1 for x in be if x.get("broad_host_access")),
        "browser_extensions_broad_and_powerful": sum(1 for x in be if x.get("broad_host_access") and x.get("powerful_permissions")),
        "projects": len(pr),
        "installed_packages_inspected": sum(p["installed_count"] for p in pr),
        "url_valued_dependencies": sum(len(p["url_deps"]) for p in pr) + sum(len(i["url_deps"]) for p in pr for i in p["installed"]),
        "installed_lifecycle_scripts": installed_lc,
        "installed_lifecycle_suspicious": installed_lc_susp,
        "installed_lifecycle_transitive": installed_lc_trans,
        "projects_with_off_registry_resolutions": sum(1 for p in pr if p["off_registry"]),
        "findings_by_severity": {k: sum(1 for f in report["findings"] if f["severity"] == k) for k in ("high", "medium", "low", "note")},
    }
    return s


def print_summary(report):
    s = report["summary"]
    m = report["meta"]
    print(f"\nunderlight {TOOL_VERSION} — {m['host']} ({m['platform']}) — {m['timestamp']} — {m['elapsed_s']}s"
          + ("  [PARTIAL — interrupted]" if m.get("interrupted") else ""))
    print("=" * 78)
    print(f"JavaScript runtimes     installed {s['runtimes_installed']:>4}   embedded in {s['runtimes_embedded_apps']} apps "
          f"[{', '.join(s['runtimes_embedded_engines']) or 'none'}]")
    print(f"V8 heap images          {s['heap_images']:>4}   user-writable {s['heap_images_user_writable']}")
    print(f"Editor extensions       {s['editor_extensions']:>4}   activate-always {s['editor_extensions_activate_always']}   "
          f"modified<{RECENT_DAYS}d {s['editor_extensions_recent']}")
    print(f"Browser extensions      {s['browser_extensions']:>4}   all-sites {s['browser_extensions_broad_host']}   "
          f"all-sites+powerful {s['browser_extensions_broad_and_powerful']}")
    print(f"Projects (package.json) {s['projects']:>4}   installed packages inspected {s['installed_packages_inspected']}")
    print(f"  URL-valued dependency specifiers        {s['url_valued_dependencies']}")
    print(f"  installed lifecycle scripts             {s['installed_lifecycle_scripts']}  "
          f"(suspicious {s['installed_lifecycle_suspicious']}, transitive {s['installed_lifecycle_transitive']})")
    print(f"  projects resolving off-registry         {s['projects_with_off_registry_resolutions']}")
    fs = s["findings_by_severity"]
    print(f"\nFindings: high {fs['high']}  medium {fs['medium']}  low {fs['low']}  note {fs['note']}")
    shown = 0
    for f in report["findings"]:
        if f["severity"] in ("high", "medium", "low"):
            print(f"  [{f['severity'].upper():6}] {f['kind']}: {f['subject']}")
            print(f"           {f['detail']}")
            shown += 1
            if shown >= 40:
                print("  ... (see report for the rest)")
                break
    print("\nCoverage (what this scan actually looked at):")
    for name in ("runtimes", "heap_images", "editor_extensions", "browser_extensions", "manifests"):
        c = report[name]["coverage"]
        cap = f"  CAPPED: {c['cap_reason']}" if c["capped"] else ""
        cloud = f"  cloud-only(not local) {c['cloud_only_skipped']}" if c.get("cloud_only_skipped") else ""
        print(f"  {name:<18} visited {c['visited']:>6}  hashed {c['hashed']:>5}  "
              f"skipped perm/size/other {c['skipped_permission']}/{c['skipped_size']}/{c['skipped_other']}  "
              f"{c['elapsed_s']}s{cloud}{cap}")


# ----------------------------------------------------------------------------
# Diff
# ----------------------------------------------------------------------------
def index_by(items, keyfn):
    out = {}
    for it in items:
        try:
            out[keyfn(it)] = it
        except Exception:
            pass
    return out


def diff_reports(base, cur):
    D = {"high": [], "medium": [], "low": [], "note": []}

    def add(sev, kind, subject, detail):
        D[sev].append({"kind": kind, "subject": subject, "detail": detail})

    # heap images — hash change with same path is the CVE-2025-55305 signal
    b = index_by(base["heap_images"]["images"], lambda i: i["path"])
    c = index_by(cur["heap_images"]["images"], lambda i: i["path"])
    for p in c.keys() - b.keys():
        add("note", "heap-image-new", p, f"New snapshot (app {c[p].get('owning_app')}).")
    for p in b.keys() - c.keys():
        add("note", "heap-image-removed", p, "Snapshot no longer present.")
    for p in b.keys() & c.keys():
        if b[p].get("sha256") and c[p].get("sha256") and b[p]["sha256"] != c[p]["sha256"]:
            app_b = b[p].get("owning_app")
            add("high", "heap-image-hash-changed", p,
                f"V8 snapshot bytes changed ({b[p]['sha256'][:12]} → {c[p]['sha256'][:12]}). Expected only when the "
                f"owning app ({app_b}) updated. If the app version did not change, treat as CVE-2025-55305-class tampering.")

    # runtimes
    b = index_by(base["runtimes"]["installed"], lambda r: r["path"])
    c = index_by(cur["runtimes"]["installed"], lambda r: r["path"])
    for p in c.keys() - b.keys():
        add("medium", "runtime-new", p, f"New JavaScript interpreter ({c[p].get('name')}) since baseline.")
    for p in b.keys() - c.keys():
        add("note", "runtime-removed", p, "Interpreter no longer present.")
    for p in b.keys() & c.keys():
        if b[p].get("sha256") != c[p].get("sha256"):
            add("low", "runtime-binary-changed", p, "Interpreter binary bytes changed (update, or replacement).")
    b = index_by(base["runtimes"]["embedded"], lambda r: r["app"])
    c = index_by(cur["runtimes"]["embedded"], lambda r: r["app"])
    for p in c.keys() - b.keys():
        add("medium", "embedded-runtime-new", p, f"App with embedded engine(s) {c[p].get('engines')} not in baseline.")
    for p in b.keys() & c.keys():
        if set(b[p].get("engines", [])) != set(c[p].get("engines", [])):
            add("medium", "embedded-runtime-engines-changed", p,
                f"Embedded engines changed {b[p].get('engines')} → {c[p].get('engines')}.")

    # editor extensions — keyed by (editor, id, version) because editors keep old
    # versions on disk side by side; main changed with SAME version is the signal
    b = index_by(base["editor_extensions"]["extensions"], lambda x: (x["editor"], x["id"], x.get("version")))
    c = index_by(cur["editor_extensions"]["extensions"], lambda x: (x["editor"], x["id"], x.get("version")))
    bids = {k[:2] for k in b}
    cids = {k[:2] for k in c}
    for k in cids - bids:
        vers = sorted({kk[2] for kk in c if kk[:2] == k}, key=str)
        add("medium", "editor-extension-new", f"{k[0]}:{k[1]}", f"Installed since baseline (v{', '.join(map(str, vers))}).")
    for k in bids - cids:
        add("note", "editor-extension-removed", f"{k[0]}:{k[1]}", "Removed since baseline.")
    for k in b.keys() & c.keys():
        bh, ch = b[k].get("main_sha256"), c[k].get("main_sha256")
        if bh and ch and bh != ch:
            add("high", "editor-extension-main-mutated", f"{k[0]}:{k[1]}",
                f"Entry file changed while version stayed {k[2]}. Extensions do not mutate in place on update; "
                "this is the silent-modification signal.")
        if b[k].get("package_json_sha256") != c[k].get("package_json_sha256"):
            add("medium", "editor-extension-manifest-mutated", f"{k[0]}:{k[1]}",
                f"package.json changed while version stayed {k[2]}.")
        if set(b[k].get("activation_events", [])) != set(c[k].get("activation_events", [])):
            add("low", "editor-extension-activation-changed", f"{k[0]}:{k[1]}",
                f"{b[k].get('activation_events')} → {c[k].get('activation_events')}.")
    for k in bids & cids:
        bv = sorted({kk[2] for kk in b if kk[:2] == k}, key=str)
        cv = sorted({kk[2] for kk in c if kk[:2] == k}, key=str)
        if bv != cv:
            add("note", "editor-extension-versions-changed", f"{k[0]}:{k[1]}", f"{bv} → {cv}.")

    # browser extensions
    b = index_by(base["browser_extensions"]["extensions"], lambda x: (x["browser"], x["profile"], x["id"], x["version"]))
    c = index_by(cur["browser_extensions"]["extensions"], lambda x: (x["browser"], x["profile"], x["id"], x["version"]))
    bids = {k[:3] for k in b}
    cids = {k[:3] for k in c}
    for k in cids - bids:
        add("medium", "browser-extension-new", "/".join(k), "Installed since baseline.")
    for k in bids - cids:
        add("note", "browser-extension-removed", "/".join(k), "Removed since baseline.")
    for k in b.keys() & c.keys():
        if b[k].get("manifest_sha256") != c[k].get("manifest_sha256"):
            add("high", "browser-extension-manifest-mutated", "/".join(k[:3]),
                f"manifest.json changed while version stayed {k[3]}.")
    # permission escalation across versions
    bperm = {}
    for k, v in b.items():
        bperm.setdefault(k[:3], set()).update(v.get("permissions", []) + v.get("host_permissions", []))
    for k, v in c.items():
        cur_p = set(v.get("permissions", []) + v.get("host_permissions", []))
        if k[:3] in bperm and cur_p - bperm[k[:3]]:
            add("medium", "browser-extension-permissions-escalated", "/".join(k[:3]),
                f"New permissions since baseline: {sorted(cur_p - bperm[k[:3]])}.")

    # manifests
    def proj_key(p):
        return p["dir"]

    b = index_by(base["manifests"]["projects"], proj_key)
    c = index_by(cur["manifests"]["projects"], proj_key)
    for d in c.keys() & b.keys():
        bu = {(u["name"], u["spec"]) for u in b[d]["url_deps"]}
        cu = {(u["name"], u["spec"]) for u in c[d]["url_deps"]}
        for n, s in cu - bu:
            add("high", "url-valued-dependency-new", f"{d} :: {n}", f"New URL-valued specifier '{s}'.")
        bl = {(i["package"], k) for i in b[d]["installed"] for k in i["lifecycle"]}
        cl = {(i["package"], k) for i in c[d]["installed"] for k in i["lifecycle"]}
        for pkg, k in cl - bl:
            inst = next((i for i in c[d]["installed"] if i["package"] == pkg), {})
            susp = any(v["suspicious"] for v in inst.get("lifecycle", {}).values())
            add("high" if susp else "medium", "installed-lifecycle-new", f"{d} :: node_modules/{pkg}",
                f"Installed package now declares a {k} script{' matching a suspicious pattern' if susp else ''}. "
                "A high-download package gaining a lifecycle script it never had is the Axios/plain-crypto-js shape.")
        bh = set(b[d]["off_registry_hosts"])
        ch = set(c[d]["off_registry_hosts"])
        for h in ch - bh:
            add("medium", "lockfile-off-registry-host-new", f"{d} :: {h}", "Lockfile now resolves to a host it did not before.")
    for d in c.keys() - b.keys():
        add("note", "project-new", d, "Project not in baseline.")
    return D


def print_diff(D, base_meta, cur_meta):
    print(f"\nDiff: baseline {base_meta.get('timestamp')} → current {cur_meta.get('timestamp')}")
    print("=" * 78)
    total = sum(len(v) for v in D.values())
    if total == 0:
        print("No changes in any collector.")
        return
    for sev in ("high", "medium", "low", "note"):
        for f in D[sev]:
            print(f"  [{sev.upper():6}] {f['kind']}: {f['subject']}")
            if sev != "note":
                print(f"           {f['detail']}")
    print(f"\n{total} change(s): " + "  ".join(f"{k} {len(v)}" for k, v in D.items()))



# ----------------------------------------------------------------------------
# explain — what is this file, which package, who pulled it in, does it match
# the tarball in the local npm cache (offline)
# ----------------------------------------------------------------------------
EXT_NOTES = {
    ".d.ts": "TypeScript declaration file (types only, no runtime code). iOS Files shows .ts as MPEG-2 video and cannot open it.",
    ".ts": "TypeScript source, or MPEG-2 transport stream — iOS assumes the latter.",
    ".mjs": "JavaScript ES module.",
    ".cjs": "JavaScript CommonJS module.",
    ".js": "JavaScript.",
    ".map": "Source map — build metadata, not executed.",
    ".json": "JSON data.",
    ".node": "Native addon (compiled machine code loaded by Node).",
    ".wasm": "WebAssembly binary module.",
}


def find_package_root(p):
    """Nearest ancestor with package.json that sits inside a node_modules directory."""
    for d in [p] + list(p.parents):
        if (d / "package.json").is_file() and "node_modules" in d.parts:
            return d
    return None


def find_project_root(p):
    """Nearest ancestor with package.json that is NOT inside node_modules."""
    for d in [p] + list(p.parents):
        if "node_modules" in d.parts:
            continue
        if (d / "package.json").is_file():
            return d
    return None


def sri_to_hex(integrity):
    """'sha512-<base64>' -> ('sha512', hex)"""
    try:
        algo, b64 = integrity.split("-", 1)
        return algo, base64.b64decode(b64).hex()
    except Exception:
        return None, None


def npm_cache_dirs():
    cands = [HOME / ".npm/_cacache"]
    if os.environ.get("npm_config_cache"):
        cands.insert(0, Path(os.environ["npm_config_cache"]) / "_cacache")
    if SYSTEM == "Windows":
        la = os.environ.get("LOCALAPPDATA")
        if la:
            cands.append(Path(la) / "npm-cache/_cacache")
    return [c for c in cands if c.exists()]


def find_cached_tarball(algo, hexdigest):
    for cache in npm_cache_dirs():
        p = cache / "content-v2" / algo / hexdigest[:2] / hexdigest[2:4] / hexdigest
        if p.is_file():
            return p
    return None


def lockfile_entry(project_root, pkg_root):
    """Return (lockfile_name, entry dict) for the installed package, from package-lock/shrinkwrap."""
    rel = pkg_root.relative_to(project_root).as_posix()
    for name in ("package-lock.json", "npm-shrinkwrap.json"):
        lf = project_root / name
        if lf.is_file():
            try:
                data = json.load(open(lf, encoding="utf-8"))
            except Exception:
                continue
            pk = data.get("packages") or {}
            if rel in pk:
                return name, pk[rel], data
            # lockfile v1: "dependencies" keyed by bare name at top level only
            deps = data.get("dependencies") or {}
            bare = rel.split("node_modules/")[-1]
            if bare in deps and rel.count("node_modules/") == 1:
                return name, deps[bare], data
    return None, None, None


def dependency_chains(lock_data, target_key, limit=5):
    """Walk package-lock v2/v3 'packages' graph backwards from target to root. Returns list of chains."""
    pk = (lock_data or {}).get("packages") or {}
    if not pk or target_key not in pk:
        return []
    # forward edges: key -> set of dependency keys, resolved by nearest-ancestor rule
    def resolve(from_key, dep_name):
        base = from_key
        while True:
            cand = (base + "/" if base else "") + "node_modules/" + dep_name
            if cand in pk:
                return cand
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx >= 0 else ""
    reverse = {}
    for key, ent in pk.items():
        for field in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            for dep in (ent.get(field) or {}):
                r = resolve(key, dep)
                if r:
                    reverse.setdefault(r, set()).add(key)
    chains = []
    stack = [(target_key, [target_key])]
    seen = set()
    while stack and len(chains) < limit:
        node, path = stack.pop()
        if node == "":
            chains.append(list(reversed(path)))
            continue
        if (node, len(path)) in seen or len(path) > 25:
            continue
        seen.add((node, len(path)))
        for parent in sorted(reverse.get(node, ())):
            if parent not in path:
                stack.append((parent, path + [parent]))
    return [[("<project root>" if k == "" else k.split("node_modules/")[-1]) for k in c] for c in chains]


SYNC_SUFFIX_RE = re.compile(r"^(.*?)(?: \d+| \(\d+\)|(?= \d+\.)|-\d+)?((?:\.[^./]+)*)$")


def _desuffix(part):
    # "helpers 2" -> "helpers"; "x 2.js" -> "x.js"; "x (1).js" -> "x.js"
    m = re.match(r"^(.*?)(?: \d+| \(\d+\))((?:\.[^./ ]+)*)$", part)
    return (m.group(1) + m.group(2)) if m else part


def compare_with_tarball(tar_path, pkg_root, target_rel=None):
    """Compare files on disk against the cached tarball. Returns dict."""
    out = {"tarball": str(tar_path), "checked": 0, "modified": [], "missing_on_disk": [], "added_on_disk": [], "target": None}
    try:
        raw = open(tar_path, "rb").read()
        try:
            raw = gzip.decompress(raw)
        except OSError:
            pass
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except Exception as e:
        out["error"] = f"could not open tarball: {e}"
        return out
    in_tar = {}
    for m in tf.getmembers():
        if not m.isfile():
            continue
        name = m.name.split("/", 1)[1] if "/" in m.name else m.name  # strip leading 'package/'
        in_tar[name] = m
    names = [target_rel] if target_rel else sorted(in_tar)
    for rel in names:
        if rel not in in_tar:
            if target_rel:
                out["target"] = {"in_tarball": False}
            continue
        disk = pkg_root / rel
        try:
            tar_bytes = tf.extractfile(in_tar[rel]).read()
        except Exception:
            continue
        out["checked"] += 1
        if not disk.is_file():
            out["missing_on_disk"].append(rel)
            if target_rel:
                out["target"] = {"in_tarball": True, "on_disk": False}
            continue
        disk_bytes = open(disk, "rb").read()
        same = hashlib.sha256(tar_bytes).digest() == hashlib.sha256(disk_bytes).digest()
        if not same:
            out["modified"].append(rel)
        if target_rel:
            out["target"] = {"in_tarball": True, "on_disk": True, "matches_tarball": same,
                             "tarball_sha256": hashlib.sha256(tar_bytes).hexdigest(),
                             "disk_sha256": hashlib.sha256(disk_bytes).hexdigest()}
    if not target_rel:
        out["sync_duplicates"] = []       # added files identical to a tarball file under a de-suffixed path
        out["sync_duplicate_dirs"] = {}   # top-level dir -> count
        out["added_by_dir"] = {}
        for dirpath, _, files in os.walk(pkg_root):
            if "node_modules" in Path(dirpath).relative_to(pkg_root).parts:
                continue
            for f in files:
                rel = (Path(dirpath) / f).relative_to(pkg_root).as_posix()
                if rel in in_tar:
                    continue
                # strip Finder/iCloud conflict suffixes: "helpers 2/x.js", "x 2.js", "x (1).js"
                parts = [_desuffix(part) for part in rel.split("/")]
                canon = "/".join(parts)
                if canon != rel and canon in in_tar:
                    try:
                        same = hashlib.sha256(tf.extractfile(in_tar[canon]).read()).digest() == \
                               hashlib.sha256(open(pkg_root / rel, "rb").read()).digest()
                    except Exception:
                        same = False
                    if same:
                        out["sync_duplicates"].append(rel)
                        top = rel.split("/")[0]
                        out["sync_duplicate_dirs"][top] = out["sync_duplicate_dirs"].get(top, 0) + 1
                        continue
                out["added_on_disk"].append(rel)
                top = rel.split("/")[0]
                out["added_by_dir"][top] = out["added_by_dir"].get(top, 0) + 1
    return out


def fetch_tarball_verified(resolved, integrity, timeout=60):
    """Download the registry tarball and REQUIRE it to match the lockfile integrity before use."""
    algo, hx = sri_to_hex(integrity or "")
    if not resolved or not hx:
        return None, "no resolved URL or integrity in lockfile"
    try:
        raw = urllib.request.urlopen(resolved, timeout=timeout).read()
    except Exception as e:
        return None, f"fetch failed: {e}"
    got = hashlib.new(algo, raw).hexdigest() if algo in hashlib.algorithms_available else None
    if got != hx:
        return None, "FETCHED TARBALL DOES NOT MATCH LOCKFILE INTEGRITY — registry content differs from what was locked"
    return raw, None


def compare_across_copies(pkg_name, version, rel_in_pkg, roots, exclude_root):
    """Find other installed copies of name@version under roots; hash the same file in each."""
    cov = Coverage()
    hashes = {}
    for root in roots:
        root = Path(root).expanduser()
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in bounded_walk(root, cov, MAX_MANIFEST_WALK_FILES, MAX_MANIFEST_WALK_DEPTH + 6):
            d = Path(dirpath)
            if d.name != pkg_name or "node_modules" not in d.parts or d == exclude_root:
                continue
            if pkg_name.startswith("@") is False and d.parent.name.startswith("@"):
                pass
            pj = d / "package.json"
            data = read_json(pj, cov, max_bytes=2 * 1024 * 1024)
            if not isinstance(data, dict) or data.get("name") != pkg_name or data.get("version") != version:
                continue
            target = d / rel_in_pkg if rel_in_pkg else None
            if target and target.is_file():
                h = sha256_file(target, cov)
                hashes.setdefault(h, []).append(str(target))
            dirnames[:] = []  # do not descend into this package's own node_modules
    return {"copies_found": sum(len(v) for v in hashes.values()), "distinct_hashes": len(hashes), "by_hash": hashes}


def explain_path(path_str, whole_package=False, fetch=False, compare_copies=False, roots=None):
    p = Path(path_str).expanduser()
    cov = Coverage()
    res = {"path": str(p), "exists": p.exists()}
    if not p.exists():
        return res
    meta = file_meta(p, cov) if p.is_file() else {"path": str(p), "is_dir": True}
    res["file"] = meta
    res["extension_note"] = EXT_NOTES.get("".join(p.suffixes[-2:]) if p.name.endswith(".d.ts") else p.suffix, None)

    pkg_root = find_package_root(p if p.is_dir() else p.parent)
    proj_root = find_project_root(pkg_root.parent if pkg_root else (p if p.is_dir() else p.parent))
    res["project_root"] = str(proj_root) if proj_root else None
    if not pkg_root:
        res["package"] = None
        res["verdict"] = "Not inside an installed package (no node_modules ancestor with package.json)."
        return res

    pj = read_json(pkg_root / "package.json", cov) or {}
    res["package"] = {
        "name": pj.get("name"), "version": pj.get("version"), "root": str(pkg_root),
        "description": (pj.get("description") or "")[:200],
        "homepage": pj.get("homepage") or (pj.get("repository") if isinstance(pj.get("repository"), str) else (pj.get("repository") or {}).get("url")),
        "lifecycle": lifecycle_from(pj),
        "url_deps": url_deps_from(pj),
        "nesting_depth": str(pkg_root).count("node_modules"),
    }
    rel_in_pkg = p.relative_to(pkg_root).as_posix() if p.is_file() else None
    res["file_in_package"] = rel_in_pkg

    if proj_root:
        lf_name, entry, lock_data = lockfile_entry(proj_root, pkg_root)
        res["lockfile"] = {"file": lf_name, "pinned": entry is not None}
        if entry:
            res["lockfile"].update({
                "version": entry.get("version"), "resolved": entry.get("resolved"),
                "integrity": entry.get("integrity"),
                "resolved_host": host_of(entry.get("resolved") or "") if entry.get("resolved") else None,
                "off_registry": bool(entry.get("resolved")) and (host_of(entry["resolved"]) not in REGISTRY_HOSTS),
                "version_matches_disk": entry.get("version") == pj.get("version"),
                "dev": bool(entry.get("dev")), "optional": bool(entry.get("optional")),
            })
            key = pkg_root.relative_to(proj_root).as_posix()
            res["dependency_chains"] = dependency_chains(lock_data, key)
            integ = entry.get("integrity")
            if integ:
                algo, hx = sri_to_hex(integ)
                tar = find_cached_tarball(algo, hx) if hx else None
                res["npm_cache"] = {"searched": [str(c) for c in npm_cache_dirs()], "tarball_found": bool(tar)}
                if tar:
                    res["npm_cache"]["comparison"] = compare_with_tarball(tar, pkg_root, None if whole_package else rel_in_pkg)
                elif fetch:
                    raw, err = fetch_tarball_verified(entry.get("resolved"), integ)
                    res["fetch"] = {"url": entry.get("resolved"), "integrity_verified": raw is not None, "error": err}
                    if raw is not None:
                        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / f"underlight-{hx[:16]}.tgz"
                        try:
                            tmp.write_bytes(raw)
                            res["fetch"]["comparison"] = compare_with_tarball(tmp, pkg_root, None if whole_package else rel_in_pkg)
                        finally:
                            try:
                                tmp.unlink()
                            except OSError:
                                pass
    else:
        res["lockfile"] = {"file": None, "pinned": False}

    if compare_copies and rel_in_pkg and res["package"]["name"]:
        res["copies"] = compare_across_copies(res["package"]["name"], res["package"]["version"], rel_in_pkg,
                                              roots or [str(HOME)], pkg_root)

    # verdict line
    v = []
    if res["package"]["name"]:
        v.append(f"{res['package']['name']}@{res['package']['version']}")
    lk = res.get("lockfile") or {}
    if lk.get("pinned"):
        v.append("pinned in " + lk["file"] + ("" if lk.get("version_matches_disk") else " (VERSION ON DISK DIFFERS FROM LOCKFILE)"))
        if lk.get("off_registry"):
            v.append("resolved OFF public registry: " + str(lk.get("resolved_host")))
    else:
        v.append("NOT pinned by any lockfile found")
    nc = res.get("npm_cache") or {}
    cmp_ = nc.get("comparison") or {}
    tgt = cmp_.get("target")
    if tgt:
        if tgt.get("in_tarball") and tgt.get("on_disk"):
            v.append("file MATCHES the registry tarball in your npm cache" if tgt.get("matches_tarball") else "file DIFFERS from the registry tarball in your npm cache")
        elif tgt.get("in_tarball") is False:
            v.append("file is NOT in the registry tarball (added after install)")
    elif nc and not nc.get("tarball_found") and not (res.get("fetch") or {}).get("integrity_verified"):
        v.append("tarball not in local npm cache — cannot verify bytes offline (use --fetch or --compare-copies)")
    if whole_package and cmp_:
        v.append(f"package check: {cmp_['checked']} files, {len(cmp_['modified'])} modified, {len(cmp_['missing_on_disk'])} missing, "
                 f"{len(cmp_['added_on_disk'])} added, {len(cmp_.get('sync_duplicates') or [])} sync-duplicates (inert copies)")
    fx = res.get("fetch") or {}
    fcmp = fx.get("comparison") or {}
    ft = fcmp.get("target")
    if fx:
        if not fx.get("integrity_verified"):
            v.append("fetch: " + str(fx.get("error")))
        elif ft and ft.get("in_tarball") and ft.get("on_disk"):
            v.append("registry tarball fetched and integrity-verified against lockfile; file "
                     + ("MATCHES" if ft.get("matches_tarball") else "DIFFERS"))
        elif whole_package and fcmp:
            v.append(f"registry tarball fetched and integrity-verified; package check: {fcmp['checked']} files, "
                     f"{len(fcmp['modified'])} modified, {len(fcmp['missing_on_disk'])} missing, "
                     f"{len(fcmp['added_on_disk'])} added, {len(fcmp.get('sync_duplicates') or [])} sync-duplicates (inert copies)")
    cp = res.get("copies")
    if cp:
        if cp["copies_found"] == 0:
            v.append("no other copies of this package@version on disk to compare")
        elif cp["distinct_hashes"] == 1 and hashlib.sha256(open(res["path"], "rb").read()).hexdigest() in cp["by_hash"]:
            v.append(f"identical to all {cp['copies_found']} other copies of this package@version on this machine")
        else:
            v.append(f"DIFFERS from other copies: {cp['copies_found']} copies, {cp['distinct_hashes']} distinct hashes")
    lc = res["package"]["lifecycle"]
    consumer = [k for k in lc if k in CONSUMER_LIFECYCLE]
    author_only = [k for k in lc if k not in CONSUMER_LIFECYCLE]
    if consumer:
        v.append("runs on install as a dependency: " + ", ".join(consumer))
    if author_only:
        v.append("author-only scripts (do not run on your install): " + ", ".join(author_only))
    res["verdict"] = "; ".join(v)
    return res


def _print_package_check(c, indent="    "):
    print(f"{indent}whole package: {c['checked']} files checked — {len(c['modified'])} modified, "
          f"{len(c['missing_on_disk'])} missing, {len(c['added_on_disk'])} added, "
          f"{len(c.get('sync_duplicates') or [])} sync-duplicates")
    for rel in c["modified"][:40]:
        print(f"{indent}  MODIFIED  {rel}")
    for rel in c["missing_on_disk"][:40]:
        print(f"{indent}  MISSING   {rel}")
    if c.get("sync_duplicate_dirs"):
        print(f"{indent}  sync-duplicate copies (byte-identical to a tarball file under a Finder/iCloud conflict name; Node never loads these):")
        for d, n in sorted(c["sync_duplicate_dirs"].items(), key=lambda t: -t[1])[:20]:
            print(f"{indent}    {d}/  ×{n}")
    if c["added_on_disk"]:
        print(f"{indent}  genuinely added (not in tarball under any name), by top-level directory:")
        for d, n in sorted((c.get("added_by_dir") or {}).items(), key=lambda t: -t[1])[:20]:
            print(f"{indent}    {d}  ×{n}")
        for rel in c["added_on_disk"][:15]:
            print(f"{indent}      {rel}")


def print_explain(res):
    print(f"\nexplain: {res['path']}")
    print("=" * 78)
    if not res.get("exists"):
        print("  does not exist"); return
    f = res.get("file") or {}
    if "size" in f:
        print(f"  size {f['size']}  modified {f['mtime']}  sha256 {(f.get('sha256') or '')[:16]}…")
    if res.get("extension_note"):
        print(f"  type: {res['extension_note']}")
    pkg = res.get("package")
    if not pkg:
        print(f"  {res.get('verdict')}"); return
    print(f"  package: {pkg['name']}@{pkg['version']}  (nesting depth {pkg['nesting_depth']})")
    if pkg.get("description"):
        print(f"           {pkg['description']}")
    if pkg.get("homepage"):
        print(f"           {pkg['homepage']}")
    print(f"  package root: {pkg['root']}")
    if res.get("file_in_package"):
        print(f"  file within package: {res['file_in_package']}")
    print(f"  project root: {res.get('project_root')}")
    lk = res.get("lockfile") or {}
    if lk.get("pinned"):
        print(f"  lockfile: {lk['file']}  version {lk.get('version')}  resolved {lk.get('resolved')}")
        print(f"            integrity {lk.get('integrity')}")
    else:
        print("  lockfile: not pinned")
    chains = res.get("dependency_chains") or []
    if chains:
        print("  why it is installed (dependency chains, root → package):")
        for c in chains:
            print("    " + " → ".join(c))
    nc = res.get("npm_cache")
    if nc:
        print(f"  npm cache: {'tarball found' if nc.get('tarball_found') else 'tarball NOT found'}  ({', '.join(nc.get('searched') or []) or 'no cache dir'})")
        cmp_ = nc.get("comparison") or {}
        if cmp_.get("error"):
            print(f"    {cmp_['error']}")
        if cmp_.get("target"):
            t = cmp_["target"]
            if t.get("in_tarball") and t.get("on_disk"):
                print(f"    this file vs tarball: {'MATCH' if t.get('matches_tarball') else 'DIFFERENT'}")
                if not t.get("matches_tarball"):
                    print(f"      tarball {t['tarball_sha256'][:16]}…  disk {t['disk_sha256'][:16]}…")
            elif t.get("in_tarball") is False:
                print("    this file is not in the registry tarball")
        if cmp_ and cmp_.get("checked") and cmp_.get("target") is None:
            _print_package_check(cmp_)
    fx = res.get("fetch")
    if fx:
        print(f"  fetch: {fx.get('url')}")
        print(f"         integrity vs lockfile: {'VERIFIED' if fx.get('integrity_verified') else 'FAILED — ' + str(fx.get('error'))}")
        c = fx.get("comparison") or {}
        t = c.get("target")
        if t and t.get("in_tarball") and t.get("on_disk"):
            print(f"         this file vs registry tarball: {'MATCH' if t.get('matches_tarball') else 'DIFFERENT'}")
        if c.get("checked") and t is None:
            _print_package_check(c, indent="         ")
    cp = res.get("copies")
    if cp:
        print(f"  other copies of this package@version on this machine: {cp['copies_found']} ({cp['distinct_hashes']} distinct hash(es) for this file)")
        for h, paths in cp["by_hash"].items():
            print(f"    {str(h)[:16]}…  ×{len(paths)}")
            for p in paths[:4]: print(f"        {p}")
    if pkg.get("lifecycle"):
        for k, v in pkg["lifecycle"].items():
            tag = "" if k in CONSUMER_LIFECYCLE else "  [author-only; does not run on your install]"
            print(f"  lifecycle {k}: {v['script'][:120]}{'  [suspicious pattern]' if v['suspicious'] else ''}{tag}")
    if pkg.get("url_deps"):
        for u in pkg["url_deps"]:
            print(f"  URL-valued dependency: {u['name']} = {u['spec']}")
    print(f"\n  → {res.get('verdict')}")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def run_scan(roots, deep, extra_heap_roots):
    t0 = time.time()
    report = {
        "meta": {
            "tool": "underlight",
            "version": TOOL_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "platform": f"{SYSTEM} {platform.release()} {platform.machine()}",
            "python": platform.python_version(),
            "user": os.environ.get("USER") or os.environ.get("USERNAME"),
            "roots": [str(Path(r).expanduser()) for r in roots],
            "deep": deep,
            "executed_anything": False,
            "network_used": False,
            "interrupted": False,
        },
        "runtimes": {"installed": [], "embedded": [], "coverage": Coverage().finish()},
        "heap_images": {"images": [], "coverage": Coverage().finish()},
        "editor_extensions": {"extensions": [], "coverage": Coverage().finish()},
        "browser_extensions": {"extensions": [], "coverage": Coverage().finish()},
        "manifests": {"projects": [], "coverage": Coverage().finish()},
    }
    stages = [
        ("runtimes", lambda: collect_runtimes()),
        ("heap_images", lambda: collect_heap_images(extra_heap_roots)),
        ("editor_extensions", lambda: collect_editor_extensions()),
        ("browser_extensions", lambda: collect_browser_extensions()),
        ("manifests", lambda: collect_manifests(roots, deep=deep)),
    ]
    try:
        for i, (name, fn) in enumerate(stages, 1):
            progress(f"[{i}/{len(stages)}] {name}…")
            report[name] = fn()
            progress(f"      done in {report[name]['coverage']['elapsed_s']}s")
    except KeyboardInterrupt:
        progress("\ninterrupted — writing partial report")
        report["meta"]["interrupted"] = True
    crosslink_snapshots_to_apps(report)
    report["findings"] = derive_findings(report)
    report["summary"] = summarize(report)
    report["meta"]["elapsed_s"] = round(time.time() - t0, 2)
    return report


def crosslink_snapshots_to_apps(report):
    """An app bundle that ships a V8 snapshot embeds V8 whether or not a string marker fired."""
    by_app = {e["app"]: e for e in report["runtimes"]["embedded"]}
    for img in report["heap_images"]["images"]:
        app = img.get("owning_app")
        if not app:
            continue
        rec = by_app.get(app)
        if rec is None:
            rec = {"app": app, "frameworks": [], "markers": {}, "main_executable": None,
                   "framework_binaries": [], "links_system_engine": [], "engines": []}
            by_app[app] = rec
            report["runtimes"]["embedded"].append(rec)
        rec.setdefault("markers", {}).setdefault("V8", [])
        if "snapshot-file-present" not in rec["markers"]["V8"]:
            rec["markers"]["V8"].append("snapshot-file-present")
        if "V8" not in rec.get("engines", []):
            rec["engines"] = sorted(set(rec.get("engines", [])) | {"V8"})


def load_report(path):
    with open(path, "r", encoding="utf-8") as f:
        r = json.load(f)
    for k in ("runtimes", "heap_images", "editor_extensions", "browser_extensions", "manifests", "meta"):
        if k not in r:
            raise SystemExit(f"{path}: not an underlight report (missing '{k}')")
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(prog="underlight", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="inventory this machine")
    s.add_argument("--out", help="write report JSON here (default ./underlight-<timestamp>.json)")
    s.add_argument("--roots", nargs="*", default=[str(HOME)], help="directories to search for package.json (default: home)")
    s.add_argument("--no-deep", action="store_true", help="do not inspect node_modules of found projects")
    s.add_argument("--heap-roots", nargs="*", default=[], help="extra directories to search for V8 snapshots")
    s.add_argument("--baseline", help="after scanning, diff against this earlier report")
    s.add_argument("--quiet", action="store_true", help="print only the JSON path")
    s.add_argument("--verbose", action="store_true", help="progress line per app / project")

    d = sub.add_parser("diff", help="compare two reports")
    d.add_argument("baseline")
    d.add_argument("current")

    e = sub.add_parser("explain", help="what is this file / package, who pulled it in, does it match the npm cache")
    e.add_argument("path")
    e.add_argument("--whole-package", action="store_true", help="compare every file in the package against the tarball")
    e.add_argument("--fetch", action="store_true",
                   help="THE ONE NETWORK OPERATION: if the tarball is not in the local npm cache, download it from the "
                        "lockfile's resolved URL and require it to match the lockfile integrity hash before comparing")
    e.add_argument("--compare-copies", action="store_true",
                   help="offline alternative: hash the same file in every other installed copy of this package@version under --roots")
    e.add_argument("--roots", nargs="*", default=[str(HOME)], help="where to look for other copies (default: home)")
    e.add_argument("--json", action="store_true", help="print JSON instead of text")

    args = ap.parse_args(argv)

    if args.cmd == "explain":
        res = explain_path(args.path, whole_package=args.whole_package, fetch=args.fetch,
                           compare_copies=args.compare_copies, roots=args.roots)
        if args.json:
            print(json.dumps(res, indent=1))
        else:
            print_explain(res)
        return 0

    if args.cmd == "scan":
        global VERBOSE
        VERBOSE = args.verbose
        report = run_scan(args.roots, not args.no_deep, args.heap_roots)
        out = Path(args.out) if args.out else Path(f"underlight-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
        if not args.quiet:
            print_summary(report)
        print(f"\nReport: {out.resolve()}")
        if args.baseline:
            base = load_report(args.baseline)
            print_diff(diff_reports(base, report), base["meta"], report["meta"])
        return 0

    if args.cmd == "diff":
        base = load_report(args.baseline)
        cur = load_report(args.current)
        print_diff(diff_reports(base, cur), base["meta"], cur["meta"])
        return 0


if __name__ == "__main__":
    sys.exit(main())
