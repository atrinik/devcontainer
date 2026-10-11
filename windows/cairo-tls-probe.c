/* SPDX-License-Identifier: MIT
 * Copyright 2026 The Atrinik Project
 */
#include <windows.h>
#include <cairo.h>
#include <cairo-win32.h>
#include <stdint.h>
#include <stdio.h>
#include "cairo-tls-rvas.h"

static int qualify(void)
{
    HMODULE module = LoadLibraryW(L"libcairo-2.dll");
    if (!module) return 1;
    const unsigned char *base = (const unsigned char *)module;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    const DWORD size = nt->OptionalHeader.SizeOfImage;
    if (!dir->VirtualAddress || dir->Size != sizeof(IMAGE_TLS_DIRECTORY64)) {
        fprintf(stderr, "Cairo TLS registration missing\n");
        return 2;
    }
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        size < sizeof(IMAGE_TLS_DIRECTORY64) || dir->VirtualAddress > size - sizeof(IMAGE_TLS_DIRECTORY64) ||
        TLS_CALLBACK_RVA >= size || TLS_INITIALIZED_FLAG_RVA > size - sizeof(LONG)) return 3;
    const IMAGE_TLS_DIRECTORY64 *tls = (const IMAGE_TLS_DIRECTORY64 *)(base + dir->VirtualAddress);
    const uintptr_t callbacks = (uintptr_t)tls->AddressOfCallBacks;
    const uintptr_t start = (uintptr_t)base;
    if (callbacks < start || callbacks > start + size - sizeof(uintptr_t)) return 3;
    int registered = 0, terminated = 0;
    for (size_t i = 0; i < 256; ++i) {
        if (callbacks + i * sizeof(uintptr_t) > start + size - sizeof(uintptr_t)) return 4;
        const uintptr_t callback = ((const uintptr_t *)callbacks)[i];
        if (!callback) { terminated = 1; break; }
        if (callback == start + TLS_CALLBACK_RVA) registered = 1;
    }
    /* Inspect before any Cairo API can lazily initialize these mutexes. */
    LONG initialized = *(const volatile LONG *)(base + TLS_INITIALIZED_FLAG_RVA);
    if (!registered || !terminated || initialized != (LONG)TLS_INITIALIZED_VALUE) {
        fprintf(stderr, "Cairo TLS callback registered=%d initialized=%ld\n", registered, initialized);
        return 5;
    }
#define RESOLVE(name) \
    __typeof__(&name) call_##name = (__typeof__(&name))GetProcAddress(module, #name); \
    if (!call_##name) return 6
    RESOLVE(cairo_image_surface_create);
    RESOLVE(cairo_surface_status);
    RESOLVE(cairo_surface_destroy);
    RESOLVE(cairo_create);
    RESOLVE(cairo_status);
    RESOLVE(cairo_destroy);
    RESOLVE(cairo_set_source_rgb);
    RESOLVE(cairo_paint);
    RESOLVE(cairo_win32_font_face_create_for_logfontw);
    RESOLVE(cairo_font_face_status);
    RESOLVE(cairo_font_face_destroy);
    RESOLVE(cairo_set_font_face);
    RESOLVE(cairo_set_font_size);
    RESOLVE(cairo_text_extents);
#undef RESOLVE
    cairo_surface_t *surface = call_cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 32, 32);
    cairo_t *context = call_cairo_create(surface);
    LOGFONTW font = {0};
    font.lfHeight = -12;
    font.lfCharSet = DEFAULT_CHARSET;
    lstrcpyW(font.lfFaceName, L"Arial");
    cairo_font_face_t *face = call_cairo_win32_font_face_create_for_logfontw(&font);
    call_cairo_set_source_rgb(context, 0.25, 0.5, 0.75);
    call_cairo_paint(context);
    call_cairo_set_font_face(context, face);
    call_cairo_set_font_size(context, 12.0);
    cairo_text_extents_t extents;
    call_cairo_text_extents(context, "TLS", &extents);
    int valid = call_cairo_surface_status(surface) == CAIRO_STATUS_SUCCESS &&
        call_cairo_status(context) == CAIRO_STATUS_SUCCESS &&
        call_cairo_font_face_status(face) == CAIRO_STATUS_SUCCESS && extents.x_advance > 0;
    call_cairo_font_face_destroy(face);
    call_cairo_destroy(context);
    call_cairo_surface_destroy(surface);
    if (!valid) return 7;
    if (!FreeLibrary(module) || GetModuleHandleW(L"libcairo-2.dll") != NULL) return 8;
    return 0;
}

int main(void)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    for (int cycle = 0; cycle < 2; ++cycle) {
        int result = qualify();
        if (result) return result;
    }
    printf("Cairo TLS pid=%lu callback_rva=%u process_attach_initialized=2 surface_font_smoke=1 explicit_unload=1 reload=1\n",
           (unsigned long)GetCurrentProcessId(), TLS_CALLBACK_RVA);
    return 0;
}
