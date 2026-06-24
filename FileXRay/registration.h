/* SPDX-License-Identifier: LGPL-3.0-or-later */
#ifndef FILEXRAY_REGISTRATION_H
#define FILEXRAY_REGISTRATION_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

HRESULT fx_register_server(const CLSID *clsid, PCWSTR module_path);
HRESULT fx_unregister_server(const CLSID *clsid);

#ifdef __cplusplus
}
#endif

#endif
