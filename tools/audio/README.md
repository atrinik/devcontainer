# SDL3_mixer Opus probe fixture

`opus-probe.opus` is an Atrinik-authored 0.25-second, 440 Hz mono tone at
48 kHz, encoded as Opus at 32 kbit/s. It exists only to prove that the image's
SDL3_mixer can enumerate and fully exercise its Opus decoder without an audio
device.

The fixture and `sdl3-mixer-probe.c` are distributed under this repository's
MIT license. The fixture was generated with:

```sh
ffmpeg -f lavfi \
  -i 'sine=frequency=440:sample_rate=48000:duration=0.25' \
  -c:a libopus -b:a 32k \
  -metadata title='Atrinik SDL3_mixer Opus probe' opus-probe.opus
```
