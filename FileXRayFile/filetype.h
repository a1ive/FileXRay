/* SPDX-License-Identifier: LGPL-3.0-or-later */
#ifndef FILEXRAY_FILETYPE_H
#define FILEXRAY_FILETYPE_H

#include <stddef.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

HRESULT fx_filetype_describe_path(const wchar_t *path, wchar_t *description, size_t description_cch);
void fx_filetype_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif
