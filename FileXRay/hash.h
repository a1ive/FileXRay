/* SPDX-License-Identifier: LGPL-3.0-or-later */
#ifndef FILEXRAY_HASH_H
#define FILEXRAY_HASH_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FX_HASH_MD5     0x00000001UL
#define FX_HASH_SHA1    0x00000002UL
#define FX_HASH_CRC32   0x00000004UL
#define FX_HASH_CRC64   0x00000008UL
#define FX_HASH_SHA256  0x00000010UL
#define FX_HASH_SHA512  0x00000020UL

typedef struct FX_HASH_RESULT
{
	DWORD requested_mask;
	DWORD completed_mask;
	wchar_t md5[33];
	wchar_t sha1[41];
	wchar_t crc32[9];
	wchar_t crc64[17];
	wchar_t sha256[65];
	wchar_t sha512[129];
} FX_HASH_RESULT;

typedef BOOL (CALLBACK *FILEXRAY_HASH_PROGRESS)(ULONGLONG bytes_done, ULONGLONG bytes_total, void *context);

HRESULT fx_hash_file(const wchar_t *path, DWORD hash_mask, volatile LONG *cancel_flag,
	FX_HASH_RESULT *result, FILEXRAY_HASH_PROGRESS progress, void *progress_context);

#ifdef __cplusplus
}
#endif

#endif
