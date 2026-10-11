/* SPDX-License-Identifier: MIT
 * Copyright 2026 The Atrinik Project
 */
#include <windows.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include "glib-tls-rvas.h"

static volatile LONG destroyed;
static void (*private_set)(GPrivate *, gpointer);
static gpointer (*private_get)(GPrivate *);
static void destroy_private(gpointer value)
{
    if (value == &destroyed)
        InterlockedIncrement(&destroyed);
}
static GPrivate private_value = G_PRIVATE_INIT(destroy_private);
static gpointer thread_main(gpointer value)
{
    private_set(&private_value, value);
    return private_get(&private_value);
}

int main(void)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    HMODULE module = LoadLibraryW(L"libglib-2.0-0.dll");
    if (!module) return 1;
    const unsigned char *base = (const unsigned char *)module;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    const DWORD size = nt->OptionalHeader.SizeOfImage;
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        !dir->VirtualAddress || dir->Size != sizeof(IMAGE_TLS_DIRECTORY64) ||
        size < sizeof(IMAGE_TLS_DIRECTORY64) || dir->VirtualAddress > size - sizeof(IMAGE_TLS_DIRECTORY64) ||
        GLIB_TLS_CALLBACK_RVA >= size || GLIB_TLS_INVOKED_FLAG_RVA > size - sizeof(gboolean)) return 2;
    const IMAGE_TLS_DIRECTORY64 *tls = (const IMAGE_TLS_DIRECTORY64 *)(base + dir->VirtualAddress);
    const uintptr_t callbacks = (uintptr_t)tls->AddressOfCallBacks;
    const uintptr_t start = (uintptr_t)base;
    if (callbacks < start || callbacks > start + size - sizeof(uintptr_t)) return 3;
    gboolean registered = FALSE, terminated = FALSE;
    for (size_t i = 0; i < 256; ++i) {
        if (callbacks + i * sizeof(uintptr_t) > start + size - sizeof(uintptr_t)) return 4;
        const uintptr_t callback = ((const uintptr_t *)callbacks)[i];
        if (!callback) { terminated = TRUE; break; }
        if (callback == start + GLIB_TLS_CALLBACK_RVA) registered = TRUE;
    }
    const gboolean invoked = *(const volatile gboolean *)(base + GLIB_TLS_INVOKED_FLAG_RVA);
    if (!registered || !terminated || invoked != TRUE) {
        fprintf(stderr, "GLib TLS callback registered=%d invoked=%d terminated=%d\n", registered, invoked, terminated);
        return 5;
    }
    /* The producer deliberately uses POSIX threads. This exercises GPrivate's
     * real thread destructor, not THREADS_WIN32-only callback cleanup. */
    private_set = (void (*)(GPrivate *, gpointer))GetProcAddress(module, "g_private_set");
    private_get = (gpointer (*)(GPrivate *))GetProcAddress(module, "g_private_get");
    GThread *(*thread_new)(const gchar *, GThreadFunc, gpointer) =
        (GThread *(*)(const gchar *, GThreadFunc, gpointer))GetProcAddress(module, "g_thread_new");
    gpointer (*thread_join)(GThread *) = (gpointer (*)(GThread *))GetProcAddress(module, "g_thread_join");
    if (!private_set || !private_get || !thread_new || !thread_join) return 6;
    GThread *thread = thread_new("tls-qualification", thread_main, (gpointer)&destroyed);
    if (thread_join(thread) != (gpointer)&destroyed || InterlockedCompareExchange(&destroyed, 0, 0) != 1)
        return 6;
    if (!FreeLibrary(module) || GetModuleHandleW(L"libglib-2.0-0.dll") != NULL) return 7;
    printf("GLib TLS pid=%lu callback_rva=%u process_attach_invoked=1 private_destructors=1 explicit_unload=1\n",
           (unsigned long)GetCurrentProcessId(), GLIB_TLS_CALLBACK_RVA);
    return 0;
}
