/* SPDX-License-Identifier: LGPL-3.0-or-later */
#ifndef FILEXRAY_PAGE_H
#define FILEXRAY_PAGE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>

#ifdef __cplusplus
extern "C" {
#endif

HRESULT fx_add_property_sheet_page(HINSTANCE instance, PCWSTR path, LPFNADDPROPSHEETPAGE add_page, LPARAM lparam);

#ifdef __cplusplus
}
#endif

#endif
