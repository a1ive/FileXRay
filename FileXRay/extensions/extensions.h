/* SPDX-License-Identifier: LGPL-3.0-or-later */
#ifndef FILEXRAY_EXTENSIONS_H
#define FILEXRAY_EXTENSIONS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HRESULT (*FX_EXTENSION_CREATE)(HWND parent, PCWSTR path, void **context);
typedef void (*FX_EXTENSION_LAYOUT)(void *context, const RECT *bounds);
typedef void (*FX_EXTENSION_DESTROY)(void *context);
typedef BOOL (*FX_EXTENSION_MESSAGE)(void *context, UINT message, WPARAM wparam,
	LPARAM lparam, LRESULT *result);

/*
 * create() creates extension-owned child controls on parent and returns their context.
 * layout() receives the available group-box content rectangle in parent client pixels.
 * destroy() releases the controls and context. message() is optional; when it handles a
 * parent dialog message, its result is returned from the dialog procedure.
 */
typedef struct FX_EXTENSION_HANDLER
{
	PCWSTR extension;
	PCWSTR title;
	FX_EXTENSION_CREATE create;
	FX_EXTENSION_LAYOUT layout;
	FX_EXTENSION_DESTROY destroy;
	FX_EXTENSION_MESSAGE message;
} FX_EXTENSION_HANDLER;

const FX_EXTENSION_HANDLER *fx_extension_find(PCWSTR extension);

extern const FX_EXTENSION_HANDLER fx_extension_dll_handler;
extern const FX_EXTENSION_HANDLER fx_extension_efi_handler;
extern const FX_EXTENSION_HANDLER fx_extension_exe_handler;
extern const FX_EXTENSION_HANDLER fx_extension_ico_handler;
extern const FX_EXTENSION_HANDLER fx_extension_iso_handler;

#ifdef __cplusplus
}
#endif

#endif
