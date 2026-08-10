#include <SDL3/SDL.h>
#include <SDL3_mixer/SDL_mixer.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    DECODE_BUFFER_BYTES = 16384,
    MAX_DECODED_BYTES = 16 * 1024 * 1024
};

static int fail(const char *message)
{
    fprintf(stderr, "SDL3_mixer Opus probe failed: %s: %s\n", message,
            SDL_GetError());
    return 1;
}

int main(int argc, char **argv)
{
    MIX_AudioDecoder *decoder = NULL;
    bool have_drmp3 = false;
    bool have_forbidden_decoder = false;
    bool have_opus = false;
    bool have_vorbis = false;
    bool have_wav = false;
    bool mixer_initialized = false;
    uint64_t decoded_bytes = 0;
    bool nonzero_pcm = false;
    int status = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s OPUS_FIXTURE\n", argv[0]);
        return 2;
    }

    if (!SDL_Init(0)) {
        return fail("could not initialize SDL");
    }
    if (!MIX_Init()) {
        status = fail("could not initialize SDL3_mixer");
        goto done;
    }
    mixer_initialized = true;

    if (MIX_Version() != SDL_MIXER_VERSION) {
        SDL_SetError("runtime and compile-time SDL3_mixer versions differ");
        status = fail("unexpected SDL3_mixer version");
        goto done;
    }

    printf("SDL3_mixer %d.%d.%d decoders:",
           SDL_VERSIONNUM_MAJOR(MIX_Version()),
           SDL_VERSIONNUM_MINOR(MIX_Version()),
           SDL_VERSIONNUM_MICRO(MIX_Version()));
    for (int index = 0; index < MIX_GetNumAudioDecoders(); ++index) {
        const char *name = MIX_GetAudioDecoder(index);
        if (name == NULL) {
            status = fail("decoder enumeration returned NULL");
            goto done;
        }
        printf(" %s", name);
        have_drmp3 = have_drmp3 || strcmp(name, "DRMP3") == 0;
        have_opus = have_opus || strcmp(name, "OPUS") == 0;
        have_vorbis = have_vorbis || strcmp(name, "STBVORBIS") == 0;
        have_wav = have_wav || strcmp(name, "WAV") == 0;
        have_forbidden_decoder = have_forbidden_decoder ||
            strcmp(name, "FLUIDSYNTH") == 0 || strcmp(name, "GME") == 0 ||
            strcmp(name, "TIMIDITY") == 0 || strcmp(name, "XMP") == 0;
    }
    putchar('\n');

    if (!have_opus) {
        SDL_SetError("required OPUS decoder is unavailable");
        status = fail("missing decoder");
        goto done;
    }
    if (!have_wav || !have_vorbis || !have_drmp3) {
        SDL_SetError("required WAV, STBVORBIS, or DRMP3 decoder is unavailable");
        status = fail("missing migration decoder");
        goto done;
    }
    if (have_forbidden_decoder) {
        SDL_SetError("a MIDI or module decoder was unexpectedly enabled");
        status = fail("forbidden decoder");
        goto done;
    }

    decoder = MIX_CreateAudioDecoder(argv[1], 0);
    if (decoder == NULL) {
        status = fail("could not open Opus fixture");
        goto done;
    }

    const SDL_AudioSpec spec = {
        .format = SDL_AUDIO_S16,
        .channels = 2,
        .freq = 48000,
    };
    int16_t buffer[DECODE_BUFFER_BYTES / sizeof(int16_t)];
    for (;;) {
        const int count = MIX_DecodeAudio(
            decoder, buffer, (int)sizeof(buffer), &spec);
        if (count < 0) {
            status = fail("Opus decoding failed");
            goto done;
        }
        if (count == 0) {
            break;
        }
        if ((count % (int)sizeof(int16_t)) != 0 ||
            decoded_bytes + (uint64_t)count > MAX_DECODED_BYTES) {
            SDL_SetError("invalid or excessive decoded PCM length");
            status = fail("invalid decoded output");
            goto done;
        }
        decoded_bytes += (uint64_t)count;
        for (int index = 0; index < count / (int)sizeof(int16_t); ++index) {
            nonzero_pcm = nonzero_pcm || buffer[index] != 0;
        }
    }

    if (decoded_bytes == 0 || !nonzero_pcm) {
        SDL_SetError("fixture produced no nonzero PCM samples");
        status = fail("empty decoded output");
        goto done;
    }

    printf("decoded %llu bytes of nonzero PCM without an audio device\n",
           (unsigned long long)decoded_bytes);
    status = 0;

done:
    MIX_DestroyAudioDecoder(decoder);
    if (mixer_initialized) {
        MIX_Quit();
    }
    SDL_Quit();
    return status;
}
