/* SPDX-License-Identifier: LGPL-3.0-or-later */
#define WIN32_LEAN_AND_MEAN
#include "filetype.h"

#include "config.h"
#include "resource.h"
#include "magic.h"

#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <strsafe.h>
#include <wchar.h>

static INIT_ONCE g_fx_magic_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_fx_magic_lock;
static magic_t g_fx_magic;
static HRESULT g_fx_magic_hr = E_FAIL;

static HRESULT load_magic_resource(magic_t magic)
{
	HMODULE module = NULL;
	HRSRC resource;
	HGLOBAL loaded_resource;
	DWORD resource_size;
	void *resource_data;
	void *buffers[1];
	size_t sizes[1];

	if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)(const void*)&fx_filetype_describe_path, &module))
		return HRESULT_FROM_WIN32(GetLastError());

	resource = FindResourceW(module, MAKEINTRESOURCEW(IDR_FILEXRAY_MAGIC_MGC), RT_RCDATA);
	if (!resource)
		return HRESULT_FROM_WIN32(GetLastError());

	resource_size = SizeofResource(module, resource);
	if (resource_size == 0)
		return HRESULT_FROM_WIN32(ERROR_RESOURCE_DATA_NOT_FOUND);

	loaded_resource = LoadResource(module, resource);
	if (!loaded_resource)
		return HRESULT_FROM_WIN32(GetLastError());

	resource_data = LockResource(loaded_resource);
	if (!resource_data)
		return HRESULT_FROM_WIN32(ERROR_RESOURCE_DATA_NOT_FOUND);

	buffers[0] = resource_data;
	sizes[0] = resource_size;
	if (magic_load_buffers(magic, buffers, sizes, ARRAYSIZE(buffers)) == -1)
		return E_FAIL;

	return S_OK;
}

static BOOL CALLBACK magic_init_once(PINIT_ONCE init_once, PVOID parameter, PVOID *context)
{
	HRESULT hr;

	UNREFERENCED_PARAMETER(init_once);
	UNREFERENCED_PARAMETER(parameter);
	UNREFERENCED_PARAMETER(context);

	InitializeCriticalSection(&g_fx_magic_lock);

	g_fx_magic = magic_open(MAGIC_NONE);
	if (!g_fx_magic)
	{
		g_fx_magic_hr = E_OUTOFMEMORY;
		return TRUE;
	}

	hr = load_magic_resource(g_fx_magic);
	if (FAILED(hr))
		goto fail;

	g_fx_magic_hr = S_OK;
	return TRUE;

fail:
	if (g_fx_magic)
	{
		magic_close(g_fx_magic);
		g_fx_magic = NULL;
	}
	g_fx_magic_hr = hr;
	return TRUE;
}

static HRESULT ensure_magic_loaded(void)
{
	if (!InitOnceExecuteOnce(&g_fx_magic_once, magic_init_once, NULL, NULL))
		return HRESULT_FROM_WIN32(GetLastError());
	return g_fx_magic_hr;
}

static HRESULT copy_magic_text(const char *text, wchar_t *description, size_t description_cch)
{
	int needed;
	int written;

	needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
	if (needed == 0)
	{
		needed = MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
		if (needed == 0)
			return HRESULT_FROM_WIN32(GetLastError());
		if ((size_t)needed > description_cch)
			return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

		written = MultiByteToWideChar(CP_ACP, 0, text, -1, description, (int)description_cch);
	}
	else
	{
		if ((size_t)needed > description_cch)
			return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

		written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, description, (int)description_cch);
	}

	if (written == 0)
		return HRESULT_FROM_WIN32(GetLastError());

	return S_OK;
}

HRESULT fx_filetype_describe_path(const wchar_t *path, wchar_t *description, size_t description_cch)
{
	HRESULT hr;
	WIN32_FILE_ATTRIBUTE_DATA attributes;
	int fd = -1;
	const char *magic_text;

	if (!path || !description || description_cch == 0)
		return E_INVALIDARG;

	description[0] = L'\0';

	if (!GetFileAttributesExW(path, GetFileExInfoStandard, &attributes))
		return HRESULT_FROM_WIN32(GetLastError());

	if ((attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
		return StringCchCopyW(description, description_cch, L"directory");

	fd = _wopen(path, _O_RDONLY | _O_BINARY | _O_NOINHERIT);
	if (fd == -1)
	{
		unsigned long doserrno = 0;
		_get_doserrno(&doserrno);
		if (doserrno != 0)
			return HRESULT_FROM_WIN32(doserrno);
		if (errno != 0)
			return HRESULT_FROM_WIN32(ERROR_OPEN_FAILED);
		return E_FAIL;
	}

	hr = ensure_magic_loaded();
	if (FAILED(hr))
		goto fail;

	EnterCriticalSection(&g_fx_magic_lock);
	magic_text = magic_descriptor(g_fx_magic, fd);
	if (magic_text)
		hr = copy_magic_text(magic_text, description, description_cch);
	else
		hr = E_FAIL;
	LeaveCriticalSection(&g_fx_magic_lock);

fail:
	if (fd != -1)
		_close(fd);

	return hr;
}
