#!/usr/bin/env python3
"""A reference transcriber for AcePaste Ingress's audio check. Everything runs on this machine.

    python tools/audio/transcribe.py recording.m4a          # prints the report as JSON
    export INGRESS_AUDIO_TRANSCRIBER="/path/to/python /path/to/tools/audio/transcribe.py"

It transcribes the recording as it is, with its quiet parts raised, and after three re-encodings a listener
would not notice (telephone bandwidth, an 8-bit telephone codec, played 6% faster). The engine compares the
transcripts (packages/core/src/audio.ts).

Needs: torch, transformers, numpy, scipy. The model is OpenAI's Whisper (MIT licence), fetched once from
Hugging Face: INGRESS_WHISPER_MODEL picks it (default openai/whisper-base, 74 M parameters). Anything that is
not a WAV file is converted with macOS's afconvert, or ffmpeg when that is installed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import numpy as np
from scipy import signal
from scipy.io import wavfile

RATE = 16000


def load(path):
    """mono float32 at 16 kHz"""
    src = path
    tmp = None
    with open(path, "rb") as f:
        head = f.read(12)
    if not (head[:4] == b"RIFF" and head[8:12] == b"WAVE"):
        tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False).name
        if shutil.which("afconvert"):
            subprocess.run(["afconvert", "-f", "WAVE", "-d", "LEI16@16000", "-c", "1", path, tmp], check=True, capture_output=True, timeout=600)
        elif shutil.which("ffmpeg"):
            subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", path, "-ac", "1", "-ar", "16000", tmp], check=True, capture_output=True, timeout=600)
        else:
            raise RuntimeError("only WAV files can be read without afconvert or ffmpeg")
        src = tmp
    try:
        rate, data = wavfile.read(src)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
    x = data.astype(np.float32)
    if data.dtype.kind in "iu":
        x /= float(np.iinfo(data.dtype).max)
    if x.ndim > 1:
        x = x.mean(axis=1)
    if rate != RATE:
        g = np.gcd(int(rate), RATE)
        x = signal.resample_poly(x, RATE // g, int(rate) // g).astype(np.float32)
    return x


def raise_quiet(x):
    """Strong level compression: every 50 ms stretch is brought toward the same loudness (up to +40 dB)."""
    win = int(0.05 * RATE)
    env = np.sqrt(signal.convolve(x * x, np.ones(win) / win, mode="same") + 1e-10)
    env = signal.convolve(env, np.ones(win * 4) / (win * 4), mode="same")
    floor = max(float(np.percentile(env, 5)), 1e-4)
    gain = np.minimum(0.1 / np.maximum(env, floor), 100.0)
    y = x * gain
    return (y / max(1.0, float(np.abs(y).max()))).astype(np.float32)


def telephone(x):
    sos = signal.butter(6, [300, 3400], btype="bandpass", fs=RATE, output="sos")
    return signal.sosfiltfilt(sos, x).astype(np.float32)


def mulaw(x):
    y = signal.resample_poly(x, 1, 2)
    y = np.clip(y / max(1e-6, float(np.abs(y).max())), -1, 1)
    q = np.round((np.sign(y) * np.log1p(255 * np.abs(y)) / np.log1p(255) + 1) / 2 * 255) / 255 * 2 - 1
    y = np.sign(q) * (np.power(256.0, np.abs(q)) - 1) / 255
    return signal.resample_poly(y, 2, 1).astype(np.float32)


def faster(x):
    return signal.resample_poly(x, 50, 53).astype(np.float32)


def main():
    if len(sys.argv) != 2:
        print("usage: transcribe.py <audio file>", file=sys.stderr)
        return 2
    try:
        x = load(sys.argv[1])
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"duration": 0, "decoded": False, "variants": [], "notes": [f"the recording could not be decoded ({str(e)[:120]})"]}))
        return 0
    notes = []
    limit = int(os.environ.get("INGRESS_AUDIO_MAX_SECONDS", "1800"))
    if len(x) > limit * RATE:
        notes.append(f"the recording is {len(x) / RATE:.0f} s long: only the first {limit} s were transcribed")
        x = x[: limit * RATE]

    import torch
    from transformers import pipeline
    from transformers.utils import logging as hf_logging

    hf_logging.set_verbosity_error()
    asr = pipeline("automatic-speech-recognition", model=os.environ.get("INGRESS_WHISPER_MODEL", "openai/whisper-base"), device="cpu", torch_dtype=torch.float32)

    def text(y):
        # nothing but a noise floor: the model would invent a "Thank you." for it
        if float(np.sqrt(np.mean(y * y))) < 0.0015:
            return ""
        # Decode in ten-second pieces. Left to itself the model stops at the first long pause, and what is said
        # after a silence is exactly what must not be skipped.
        kw = {"chunk_length_s": 10} if len(y) > 10 * RATE else {}
        out = asr({"raw": y, "sampling_rate": RATE}, generate_kwargs={"task": "transcribe", "temperature": 0.0, "no_repeat_ngram_size": 4}, **kw)
        return str(out.get("text", "")).strip()

    variants = [
        {"name": "as heard", "kind": "heard", "text": text(x)},
        {"name": "quiet parts raised", "kind": "quiet", "text": text(raise_quiet(x))},
        {"name": "telephone bandwidth", "kind": "reencoded", "text": text(telephone(x))},
        {"name": "8-bit telephone codec", "kind": "reencoded", "text": text(mulaw(x))},
        {"name": "6% faster", "kind": "reencoded", "text": text(faster(x))},
    ]
    print(json.dumps({"duration": round(len(x) / RATE, 2), "decoded": True, "variants": variants, "notes": notes}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
