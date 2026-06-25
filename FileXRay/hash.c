/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "hash.h"

#include <bcrypt.h>
#include <strsafe.h>

#pragma comment(lib, "bcrypt.lib")

#define FX_HASH_BUFFER_SIZE (1024U * 1024U)
#define FX_CRC64_INIT 0xffffffffffffffffULL
#define FX_CRC64_POLY 0xc96c5795d7870f42ULL

typedef struct FX_CNG_HASH
{
	BCRYPT_ALG_HANDLE algorithm;
	BCRYPT_HASH_HANDLE hash;
	PUCHAR object;
	DWORD object_length;
	DWORD digest_length;
	UCHAR digest[64];
} FX_CNG_HASH;

static HRESULT fx_cng_init(FX_CNG_HASH *context, LPCWSTR algorithm_id)
{
	HRESULT hr = E_FAIL;
	NTSTATUS status;
	DWORD returned = 0;

	ZeroMemory(context, sizeof(*context));

	status = BCryptOpenAlgorithmProvider(&context->algorithm, algorithm_id, NULL, 0);
	if (status < 0)
	{
		hr = HRESULT_FROM_NT(status);
		goto fail;
	}

	status = BCryptGetProperty(context->algorithm, BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&context->object_length, sizeof(context->object_length), &returned, 0);
	if (status < 0)
	{
		hr = HRESULT_FROM_NT(status);
		goto fail;
	}

	status = BCryptGetProperty(context->algorithm, BCRYPT_HASH_LENGTH,
		(PUCHAR)&context->digest_length, sizeof(context->digest_length), &returned, 0);
	if (status < 0)
	{
		hr = HRESULT_FROM_NT(status);
		goto fail;
	}
	if (context->digest_length > sizeof(context->digest))
	{
		hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
		goto fail;
	}

	context->object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, context->object_length);
	if (!context->object)
	{
		hr = E_OUTOFMEMORY;
		goto fail;
	}

	status = BCryptCreateHash(context->algorithm, &context->hash,
		context->object, context->object_length, NULL, 0, 0);
	if (status < 0)
	{
		hr = HRESULT_FROM_NT(status);
		goto fail;
	}

	hr = S_OK;

fail:
	if (FAILED(hr))
	{
		if (context->hash)
			BCryptDestroyHash(context->hash);
		if (context->object)
			HeapFree(GetProcessHeap(), 0, context->object);
		if (context->algorithm)
			BCryptCloseAlgorithmProvider(context->algorithm, 0);
		ZeroMemory(context, sizeof(*context));
	}

	return hr;
}

static void fx_cng_destroy(FX_CNG_HASH *context)
{
	if (context->hash)
		BCryptDestroyHash(context->hash);
	if (context->object)
		HeapFree(GetProcessHeap(), 0, context->object);
	if (context->algorithm)
		BCryptCloseAlgorithmProvider(context->algorithm, 0);

	ZeroMemory(context, sizeof(*context));
}

static HRESULT fx_cng_update(FX_CNG_HASH *context, const BYTE *data, DWORD length)
{
	NTSTATUS status = BCryptHashData(context->hash, (PUCHAR)data, length, 0);

	if (status < 0)
		return HRESULT_FROM_NT(status);

	return S_OK;
}

static HRESULT fx_cng_finish(FX_CNG_HASH *context)
{
	NTSTATUS status = BCryptFinishHash(context->hash, context->digest, context->digest_length, 0);

	if (status < 0)
		return HRESULT_FROM_NT(status);

	return S_OK;
}

static HRESULT fx_hex_bytes(const BYTE *data, DWORD length, wchar_t *output, size_t output_cch)
{
	static const wchar_t hex[] = L"0123456789abcdef";
	DWORD i;

	if (output_cch < ((size_t)length * 2U) + 1U)
		return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

	for (i = 0; i < length; i++)
	{
		output[i * 2U] = hex[data[i] >> 4];
		output[i * 2U + 1U] = hex[data[i] & 0x0f];
	}
	output[length * 2U] = L'\0';

	return S_OK;
}

static void fx_crc32_table(DWORD table[256])
{
	DWORD i;

	for (i = 0; i < 256U; i++)
	{
		DWORD crc = i;
		DWORD bit;

		for (bit = 0; bit < 8U; bit++)
			crc = (crc & 1U) ? ((crc >> 1) ^ 0xedb88320UL) : (crc >> 1);

		table[i] = crc;
	}
}

static DWORD fx_crc32_update(DWORD crc, const DWORD table[256], const BYTE *data, DWORD length)
{
	DWORD i;

	for (i = 0; i < length; i++)
		crc = table[(crc ^ data[i]) & 0xffU] ^ (crc >> 8);

	return crc;
}

static void fx_crc64_table(ULONGLONG table[256])
{
	DWORD i;

	for (i = 0; i < 256U; i++)
	{
		ULONGLONG crc = i;
		DWORD bit;

		for (bit = 0; bit < 8U; bit++)
			crc = (crc & 1ULL) ? ((crc >> 1) ^ FX_CRC64_POLY) : (crc >> 1);

		table[i] = crc;
	}
}

static ULONGLONG fx_crc64_update(ULONGLONG crc, const ULONGLONG table[256], const BYTE *data, DWORD length)
{
	DWORD i;

	for (i = 0; i < length; i++)
		crc = table[(crc ^ data[i]) & 0xffU] ^ (crc >> 8);

	return crc;
}

static HRESULT fx_prepare_hashes(DWORD hash_mask, FX_CNG_HASH *md5,
	FX_CNG_HASH *sha1, FX_CNG_HASH *sha256, FX_CNG_HASH *sha512)
{
	HRESULT hr = S_OK;

	if ((hash_mask & FX_HASH_MD5) != 0)
	{
		hr = fx_cng_init(md5, BCRYPT_MD5_ALGORITHM);
		if (FAILED(hr))
			goto fail;
	}
	if ((hash_mask & FX_HASH_SHA1) != 0)
	{
		hr = fx_cng_init(sha1, BCRYPT_SHA1_ALGORITHM);
		if (FAILED(hr))
			goto fail;
	}
	if ((hash_mask & FX_HASH_SHA256) != 0)
	{
		hr = fx_cng_init(sha256, BCRYPT_SHA256_ALGORITHM);
		if (FAILED(hr))
			goto fail;
	}
	if ((hash_mask & FX_HASH_SHA512) != 0)
	{
		hr = fx_cng_init(sha512, BCRYPT_SHA512_ALGORITHM);
		if (FAILED(hr))
			goto fail;
	}

fail:
	return hr;
}

static HRESULT fx_finish_hashes(DWORD hash_mask, FX_HASH_RESULT *result,
	FX_CNG_HASH *md5, FX_CNG_HASH *sha1, FX_CNG_HASH *sha256, FX_CNG_HASH *sha512,
	DWORD crc32, ULONGLONG crc64)
{
	HRESULT hr = S_OK;

	if ((hash_mask & FX_HASH_MD5) != 0)
	{
		hr = fx_cng_finish(md5);
		if (FAILED(hr))
			goto fail;
		hr = fx_hex_bytes(md5->digest, md5->digest_length, result->md5, ARRAYSIZE(result->md5));
		if (FAILED(hr))
			goto fail;
		result->completed_mask |= FX_HASH_MD5;
	}
	if ((hash_mask & FX_HASH_SHA1) != 0)
	{
		hr = fx_cng_finish(sha1);
		if (FAILED(hr))
			goto fail;
		hr = fx_hex_bytes(sha1->digest, sha1->digest_length, result->sha1, ARRAYSIZE(result->sha1));
		if (FAILED(hr))
			goto fail;
		result->completed_mask |= FX_HASH_SHA1;
	}
	if ((hash_mask & FX_HASH_CRC32) != 0)
	{
		hr = StringCchPrintfW(result->crc32, ARRAYSIZE(result->crc32), L"%08lx", crc32 ^ 0xffffffffUL);
		if (FAILED(hr))
			goto fail;
		result->completed_mask |= FX_HASH_CRC32;
	}
	if ((hash_mask & FX_HASH_CRC64) != 0)
	{
		hr = StringCchPrintfW(result->crc64, ARRAYSIZE(result->crc64), L"%016I64x",
			(unsigned __int64)(crc64 ^ FX_CRC64_INIT));
		if (FAILED(hr))
			goto fail;
		result->completed_mask |= FX_HASH_CRC64;
	}
	if ((hash_mask & FX_HASH_SHA256) != 0)
	{
		hr = fx_cng_finish(sha256);
		if (FAILED(hr))
			goto fail;
		hr = fx_hex_bytes(sha256->digest, sha256->digest_length, result->sha256, ARRAYSIZE(result->sha256));
		if (FAILED(hr))
			goto fail;
		result->completed_mask |= FX_HASH_SHA256;
	}
	if ((hash_mask & FX_HASH_SHA512) != 0)
	{
		hr = fx_cng_finish(sha512);
		if (FAILED(hr))
			goto fail;
		hr = fx_hex_bytes(sha512->digest, sha512->digest_length, result->sha512, ARRAYSIZE(result->sha512));
		if (FAILED(hr))
			goto fail;
		result->completed_mask |= FX_HASH_SHA512;
	}

fail:
	return hr;
}

HRESULT fx_hash_file(const wchar_t *path, DWORD hash_mask, volatile LONG *cancel_flag,
	FX_HASH_RESULT *result, FILEXRAY_HASH_PROGRESS progress, void *progress_context)
{
	HRESULT hr = E_FAIL;
	HANDLE file = INVALID_HANDLE_VALUE;
	BYTE *buffer = NULL;
	LARGE_INTEGER file_size;
	ULONGLONG bytes_done = 0;
	FX_CNG_HASH md5;
	FX_CNG_HASH sha1;
	FX_CNG_HASH sha256;
	FX_CNG_HASH sha512;
	DWORD crc32_table[256];
	ULONGLONG crc64_table[256];
	DWORD crc32 = 0xffffffffUL;
	ULONGLONG crc64 = FX_CRC64_INIT;

	ZeroMemory(&md5, sizeof(md5));
	ZeroMemory(&sha1, sizeof(sha1));
	ZeroMemory(&sha256, sizeof(sha256));
	ZeroMemory(&sha512, sizeof(sha512));

	if (!path || !result || hash_mask == 0)
		return E_INVALIDARG;

	ZeroMemory(result, sizeof(*result));
	result->requested_mask = hash_mask;

	if ((hash_mask & FX_HASH_CRC32) != 0)
		fx_crc32_table(crc32_table);
	if ((hash_mask & FX_HASH_CRC64) != 0)
		fx_crc64_table(crc64_table);

	hr = fx_prepare_hashes(hash_mask, &md5, &sha1, &sha256, &sha512);
	if (FAILED(hr))
		goto fail;

	file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	if (!GetFileSizeEx(file, &file_size))
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	buffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, FX_HASH_BUFFER_SIZE);
	if (!buffer)
	{
		hr = E_OUTOFMEMORY;
		goto fail;
	}

	if (progress)
		progress(0, (ULONGLONG)file_size.QuadPart, progress_context);

	for (;;)
	{
		DWORD bytes_read = 0;

		if (cancel_flag && InterlockedCompareExchange((LONG *)cancel_flag, 0, 0) != 0)
		{
			hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
			goto fail;
		}

		if (!ReadFile(file, buffer, FX_HASH_BUFFER_SIZE, &bytes_read, NULL))
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			goto fail;
		}
		if (bytes_read == 0)
			break;

		if ((hash_mask & FX_HASH_MD5) != 0)
		{
			hr = fx_cng_update(&md5, buffer, bytes_read);
			if (FAILED(hr))
				goto fail;
		}
		if ((hash_mask & FX_HASH_SHA1) != 0)
		{
			hr = fx_cng_update(&sha1, buffer, bytes_read);
			if (FAILED(hr))
				goto fail;
		}
		if ((hash_mask & FX_HASH_SHA256) != 0)
		{
			hr = fx_cng_update(&sha256, buffer, bytes_read);
			if (FAILED(hr))
				goto fail;
		}
		if ((hash_mask & FX_HASH_SHA512) != 0)
		{
			hr = fx_cng_update(&sha512, buffer, bytes_read);
			if (FAILED(hr))
				goto fail;
		}
		if ((hash_mask & FX_HASH_CRC32) != 0)
			crc32 = fx_crc32_update(crc32, crc32_table, buffer, bytes_read);
		if ((hash_mask & FX_HASH_CRC64) != 0)
			crc64 = fx_crc64_update(crc64, crc64_table, buffer, bytes_read);

		bytes_done += bytes_read;
		if (progress && !progress(bytes_done, (ULONGLONG)file_size.QuadPart, progress_context))
		{
			hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
			goto fail;
		}
	}

	hr = fx_finish_hashes(hash_mask, result, &md5, &sha1, &sha256, &sha512, crc32, crc64);
	if (FAILED(hr))
		goto fail;

	if (progress)
		progress((ULONGLONG)file_size.QuadPart, (ULONGLONG)file_size.QuadPart, progress_context);

fail:
	if (buffer)
		HeapFree(GetProcessHeap(), 0, buffer);
	if (file != INVALID_HANDLE_VALUE)
		CloseHandle(file);
	fx_cng_destroy(&md5);
	fx_cng_destroy(&sha1);
	fx_cng_destroy(&sha256);
	fx_cng_destroy(&sha512);

	return hr;
}
