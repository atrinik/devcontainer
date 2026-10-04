#include <SDL3/SDL.h>
#include <SDL3_image/SDL_image.h>
#include <SDL3_ttf/SDL_ttf.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2 || !SDL_Init(0) || !TTF_Init()) {
        return 1;
    }
    SDL_Surface *source = SDL_CreateSurface(8, 8, SDL_PIXELFORMAT_RGBA32);
    if (!source || !SDL_FillSurfaceRect(source, NULL,
            SDL_MapSurfaceRGBA(source, 40, 160, 220, 255)) ||
            !IMG_SavePNG(source, "probe.png") ||
            !IMG_SaveJPG(source, "probe.jpg", 95)) {
        fprintf(stderr, "image encoder: %s\n", SDL_GetError());
        return 1;
    }
    SDL_Surface *png = IMG_Load("probe.png");
    SDL_Surface *jpg = IMG_Load("probe.jpg");
    TTF_Font *font = TTF_OpenFont(argv[1], 16);
    SDL_Color white = {255, 255, 255, 255};
    SDL_Surface *text = font ? TTF_RenderText_Blended(font, "Atrinik", 0, white) : NULL;
    if (!png || !jpg || png->w != 8 || jpg->h != 8 || !text || text->w < 1) {
        fprintf(stderr, "image/font decoder: %s\n", SDL_GetError());
        return 1;
    }
    SDL_DestroySurface(text);
    TTF_CloseFont(font);
    SDL_DestroySurface(jpg);
    SDL_DestroySurface(png);
    SDL_DestroySurface(source);
    TTF_Quit();
    SDL_Quit();
    puts("PNG/JPEG roundtrip and TrueType glyph rasterization passed without devices");
    return 0;
}
