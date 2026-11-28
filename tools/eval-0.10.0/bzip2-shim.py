#!/usr/bin/env python3
# minimal bzip2 shim (decompress only) for `tar -j` in a sandbox without the bzip2 binary
import bz2, sys, shutil
args=[a for a in sys.argv[1:] if a.startswith('-')]
if not any('d' in a for a in args): sys.exit("shim supports -d only")
with bz2.open(sys.stdin.buffer) as f: shutil.copyfileobj(f, sys.stdout.buffer, 1<<20)
