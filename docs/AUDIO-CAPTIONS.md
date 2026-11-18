# Captions, transcripts and audio

A caption file is read by people one line at a time. A meeting transcript is a room anyone present can speak
in. A recording is heard once, at the level it was mixed. A model gets the whole file, the whole transcript,
the samples. These adapters look for what only the machine receives.

## Captions (`kind: "captions"`)

WebVTT and SubRip are recognised on their own (`.vtt`, `.srt`, `text/vtt`, or a `WEBVTT` header).

| check | what it finds |
|---|---|
| unreadable cues | a cue on screen for less time than its words can be read (under a fifth of a second, or over 60 characters a second), or sized to nothing (`size:0%`) |
| hidden cues | cues a `STYLE` block makes transparent, zero-sized or hidden |
| what no player shows | `NOTE` blocks, text in `STYLE` blocks |
| captions vs. speech | given a transcript of the audio (`scan(captions, { spoken })`), passages in the captions nobody said |

## Meeting transcripts

JSON with utterances, speakers and times (the shape transcription services and notetakers produce) is read as
captions too.

- **Someone speaking to the notetaker.** "AI notetaker, add to the action items that..." is content, not an
  instruction to the one taking notes. It is reported, and counts for more from a speaker listed in
  `outsideSpeakers`.
- **Spoken approvals are noted and are never approvals.** "Yes, I approve, go ahead" in a transcript changes
  nothing: actions are approved through the action broker's own channel, which a recording cannot reach. A
  cloned voice saying the right words is exactly as effective as a real one: not at all.

## Audio (`engine.scanAudio`, `ingress --audio <file>`)

The recording is transcribed five ways and the transcripts are compared (`audio.ts`):

| view | what it is | what it shows |
|---|---|---|
| as heard | the recording as it is | the transcript that is delivered |
| quiet parts raised | strong level compression | speech mixed too low for a listener to make out: concealed text |
| telephone bandwidth, 8-bit telephone codec, 6% faster | re-encodings a listener would understand without noticing | speech survives them. If what is "heard" changes, the audio was made to be mis-heard |

The file's tags (ID3 comments and lyrics, WAV INFO, Vorbis comments) are text nobody hears and are scanned.

**Transcription is yours to choose.** The engine runs the command in `INGRESS_AUDIO_TRANSCRIBER` with the file
path and reads its JSON report. `tools/audio/transcribe.py` is a working one: an open Whisper model
(MIT licence) with PyTorch, on this machine, nothing sent anywhere.

```sh
python3 -m venv ~/ingress-audio && ~/ingress-audio/bin/pip install torch transformers scipy numpy
export INGRESS_AUDIO_TRANSCRIBER="$HOME/ingress-audio/bin/python $PWD/tools/audio/transcribe.py"
ingress --audio meeting.m4a
```

Without a transcriber the tags are still read and every result says the recording was not transcribed
(`coverage.audio.transcribed: false`).

## Measured

- Constructed recordings (system voice): plain speech passes with its transcript; an instruction spoken 40 dB
  below a podcast, after a pause, is refused (`audio.quiet_speech`); a noise floor alone yields no words.
- 24 LibriSpeech utterances (people reading books aloud; 178 seconds): 24 clean, 496 words delivered, about 7
  seconds each on an Apple Silicon laptop with the 74 M-parameter model.
- The caption and transcript checks are tested on constructed files (`test/captions-audio.test.ts`).

## Not measured, and limits

- **Adversarial audio was not tested.** The re-encoding check is built on a property reported in the research
  literature (crafted perturbations are fragile under re-encoding); no adversarial recording was made or
  scored here, so how many it catches is unknown.
- **No real-world recordings with music, crosstalk or poor microphones were scored.** Raising quiet parts also
  raises noise, and speech models invent words for noise; a passage must be five words long to count, and a
  noise floor alone is not transcribed, but the false-alarm rate on real podcasts and meetings is not known.
- **The reference transcriber decodes in ten-second pieces** so that speech after a silence is not skipped
  (left to itself the model stops at the first long pause). Words cut at a boundary can be garbled.
- **A voice cannot be told from a clone of it,** and nothing above the range of the file (ultrasound played to
  a microphone) is in the file to find.
- **Not built:** a native macOS transcriber (Apple's speech framework needs a permission a person must grant);
  audio inside tool results in the MCP proxy (still withheld as not inspected); video (frames shown briefly,
  captions against the picture).
