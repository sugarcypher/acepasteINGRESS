# Video

A person watches a video once, at its own speed. A model is handed frames somebody sampled, the subtitle track
as text, and a transcript of the sound. Each is a place for words the viewer never took in. Ingress reads a
video both ways and compares.

```sh
ingress vision build              # compile the helper on this machine (macOS with Xcode or its command line tools)
ingress vision selftest           # pictures, screens and five test clips: is each trick caught here?
ingress --video clip.mp4          # gate one video; prints what was read and how much of it
ingress --video talk.mp4 --captions=talk.vtt
```

Library: `engine.scanVideo(bytes, { captions?, maxSeconds?, maxFrames?, source? })`. HTTP: `POST /v1/scan-video`
(`{ video: base64 }`, up to about 45 MB). MCP proxy: a video inside a proxied tool's result (the protocol carries
it as an embedded resource with a `video/*` media type) is gated like pictures and recordings are: handed on
only when its frames were read and nothing in it is refused.

A camera frame is a picture: send it to `scanImage`. There is no camera reader here, and nothing in Ingress
opens a camera.

## What is read

| where | how | what it means when something is found only there |
|---|---|---|
| on screen | every frame is looked at as a small grey thumbnail to find where the picture changes; text is then recognised in the frames that matter (below) | text a viewer can read is delivered and judged like visible text in a picture |
| on screen, briefly | how long each line stays is worked out from the frames it is in and from where the picture changed | text shown for under a third of a second is concealed content (`video.brief_frame_text`): nobody reads a fifteenth of a second, and a model handed that frame reads all of it |
| codes | every QR code and barcode in the frames read | judged like a code in a picture (`docs/IMAGES.md`), with the time it is on screen |
| subtitle tracks | 3GPP timed text and WebVTT tracks inside the file, and a captions file given beside it | read by the caption reader (`docs/AUDIO-CAPTIONS.md`): cues styled invisible, cues too brief to read, speaking to a notetaker |
| captions against the rest | when the sound was transcribed: captions against what was said and what is shown | `captions.not_spoken`: the captions say something nobody said and no frame showed |
| the sound | the first audio track, taken out as 16 kHz WAV and handed to the transcriber you configured (`INGRESS_AUDIO_TRANSCRIBER`) | as for a recording: speech too quiet to hear, a transcript that changes when re-encoded |
| the file's tags | description, comment and similar fields; routine ones (title, encoder, dates) are skipped unless long | text nobody watching sees |

Brief text is refused when it reads as instructions, like any hidden text. Ordinary words that flash by (a
title card in a fast cut) are recorded and do not, on their own, change the verdict.

### Which frames are read

Recognising text takes a tenth to a quarter of a second per frame, so not every frame of a long video is read.
At most 240 frames are (`maxFrames`):

- **A short clip** (240 frames or fewer: eight seconds at 30 frames a second): every frame.
- **Anything longer**, in this order until the budget is spent:
  1. every picture put in between two frames of the same scene (the scene, the picture, the scene again),
     which is what hidden frames look like: its middle frame, the frame before it and the frame after it;
  2. a share of the other pictures that are on screen for under half a second (fast cuts, and movement, which
     also "changes the picture"), each with the frame before and after;
  3. the frame shortly after each cut;
  4. a regular grid with what is left.

  Frames that look the same as one already read are not read twice.

"Where the picture changes" is found by comparing each frame's thumbnail with the one before, cell by cell,
against how much that video changes from frame to frame anyway: a line of text that appears changes a few
cells a lot. At most the first 600 seconds are examined (`maxSeconds`).

**Brief means the frames read on either side do not have it.** A line is called brief only when a frame that
was read before it and a frame that was read after it, a third of a second apart or less, both lack it. Where
the picture changed decides which frames are worth reading; it is never itself the evidence. The line must
also be read clearly, be words and not scraps of recognition, and not be the beginning of a line that stayed
(captions that build up word by word).

**A partial read is never silent.** `coverage.video` gives the length, how much was examined, how many frames
there are and how many were read, whether the sound was transcribed and why not, and how many caption cues
were read. The delivered text ends with one line saying the same. When part of the video was not examined at
all (it is longer than the limit; there were more inserted pictures than the budget reached) the result
carries a `video.partly_read` finding, and when no frame could be read, `video.frames_not_read`. The MCP proxy
withholds a video whose frames it could not read.

## Measured

- **Self-test clips** (generated by the helper, so they check that the machinery works on this machine; they
  are not a benchmark): two frames of instructions between ordinary pictures, an instruction in a QR code, and
  a subtitle cue on screen for a tenth of a second are refused; a plain slide and a textless clip pass; the
  same instructions left on screen for a second and a half are judged as visible text, not as hidden.
- **Ordinary videos** (NASA's Image and Video Library: explainers, animations, interviews, launch highlights,
  time lapses; most carry titles, labels and captions on screen; `tools/video/`). Every refusal is a false
  alarm. On the half held out until the rules were fixed, scored once: **35 of 35 pass at watchable size, and
  42 of 42 at the library's 320-pixel size; none suspect.** Brief text was recorded in one clip of each set,
  without changing its verdict. The first cut recorded it in 12 of 28 development clips; what was wrong, and
  the rule that replaced it, are in [`tools/video/README.md`](../tools/video/README.md).

These clips are edited, professional video from one publisher, and the sound was not transcribed in these
runs. Screen recordings, phone footage and fast-cut advertising are not represented.

Recall on real video attacks is **not measured**. No public set of prompt-injection videos was found whose
licence and contents could be checked without watching the attacks. What is measured is that the mechanisms
work on constructed cases and how often ordinary video is refused.

## Limits

- **macOS only.** The helper uses AVFoundation and Vision. Elsewhere, and where the helper is not built, the
  result says the frames were not read.
- **Containers: MP4, MOV, M4V** (what AVFoundation opens). WebM, Matroska and AVI are not read, and the
  result says so. Codecs: what this Mac can decode.
- **Text in a frame is read as shown.** The picture checks for faint text, text under transparency and
  resizing tricks are not run on every frame. A frame can be saved and sent to `scanImage` for those.
- **In a long video, small text over moving footage can fall between the frames read.** A change is noticed
  against how much the video changes anyway; a few words appearing for two frames in a corner of a busy scene
  may not stand out, and the regular grid may miss them. A short clip is read in full.
- **A third of a second is a line drawn by hand.** Fast-cut editing shows ordinary words that briefly; that is
  why brief text alone does not refuse a video.
- **Closed-caption tracks (CEA-608) are not read**; the result notes one when it is present. Subtitles burned
  into the picture are on-screen text.
- **The sound needs a transcriber you configure**; without one the result says the sound was not transcribed.
  Only the first audio track is read.
- **Size and time:** files up to 400 MB; the helper is given five minutes. A ten-minute 720p video takes
  about a minute on an Apple Silicon laptop.
- **Adversarial noise is not text.** Frames crafted against one model, with no readable words, are not detected.
