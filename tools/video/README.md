# Video false-alarm check

How often does the video gate refuse an ordinary video? These tools download ordinary clips and scan them.
Every one is benign, so every refusal is a false alarm to explain.

```sh
npm run build && ingress vision build
node tools/video/fetch-nasa.mjs ~/ingress-video 6                   # <dir>/dev and <dir>/holdout, by a hash of each clip's id
node tools/video/fetch-nasa.mjs ~/ingress-video-small 7 --prefer=mobile
node tools/video/score-videos.mjs ~/ingress-video/dev               # verdicts, finding kinds and coverage; never text
```

The clips come from NASA's Image and Video Library (images.nasa.gov): explainers, mission overviews,
animations, interviews, launch highlights, time lapses, infographics. NASA's own material is generally not
copyrighted; each clip's page says where it came from. They are for local measurement and are not
redistributed here. Most carry text on screen (titles, labels, lower thirds, captions burned into the
picture), which is what makes them worth scanning.

Which half a clip belongs to is decided by a hash of its id when it is downloaded, before anything is scanned.

## Results (2026-11-20, engine 0.9.27, Apple Silicon, no transcriber configured)

Two downloads of mostly the same clips: at the library's "small" size (what a person would watch), and at
its "mobile" size (320 pixels wide, where most text on screen is too small to be recognised at all).

| step | set | clips | clean | `video.brief_frame_text` present | `video.partly_read` |
|---|---|---|---|---|---|
| first cut | dev, small size | 28 | 28 | **12** | 18 |
| first cut | dev, mobile size | 33 | 33 | **13** | 19 |
| brief only on the evidence of frames read; words, clearly read | dev, small size | 28 | 28 | 2 | 0 |
| the same rules | dev, mobile size | 33 | 33 | 0 | 1 |
| the final rules | **hold-out, small size, scored once** | **35** | **35** | 1 | 1 |
| the final rules | **hold-out, mobile size, scored once** | **42** | **42** | 1 | 4 |

**The number to quote: 35 of 35 ordinary videos pass at watchable size (42 of 42 at mobile size), none
suspect.** The two hold-out sets are the same half of the library at two sizes, so they are one measurement
read twice, not two.

What the first cut got wrong, on the development half:

- **It called text brief on the strength of where the picture changed.** "Where the picture changes" was
  computed from small thumbnails, and movement in a scene counts as change. A line read in one frame, inside a
  "picture" that movement had cut down to a few frames, was reported as shown for those few frames: 12 of 28
  ordinary clips. None was refused (ordinary words that flash by do not change the verdict on their own), but
  each sat at 0.19 against a suspect line of 0.25.
- **The rule now:** a line is brief only if the frames *read* right before and right after it do not have it.
  When frames are selected, the helper reads the frame before and the frame after every short-lived picture it
  chooses, so that evidence exists. The line must be read clearly (confidence 0.8 or more), be words and not
  scraps, and not be in the neighbouring frames in some other reading of it.
- **"Partly read" meant too much.** Every picture on screen for under half a second counted, and movement
  makes hundreds of those. The finding is now kept for real gaps: part of the video not examined, or pictures
  put in between two frames of the same scene (the scene, the picture, the scene again: what hidden frames
  look like) that the frame budget did not reach. Fast cuts and movement that were only sampled are reported
  in the coverage.

About 27 seconds per clip at small size (clips of half a minute to ten minutes; 240 frames read from each),
more when other work is running.

## What the numbers do not say

- **They measure false alarms, not attacks caught.** No public set of prompt-injection videos was found whose
  licence and contents could be checked without watching the attacks. The self-test clips
  (`ingress vision selftest`) show the mechanisms work on constructed cases: two frames of instructions between
  ordinary pictures, an instruction in a QR code, a subtitle cue nobody can read.
- **One publisher.** These are edited, professional videos from one agency. Screen recordings, phone footage,
  advertising with fast-cut text and video with burned-in captions in other scripts are not represented.
- **The sound was not transcribed** in these runs (no transcriber was configured), so every result says so
  (`audio.not_transcribed`); nothing about captions against speech was exercised on real video.
- **Subtitle tracks were not exercised on real video.** No caption finding came up in any clip, and how many
  of them carry a subtitle track at all was not counted. That path is tested on a clip the helper writes.
