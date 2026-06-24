/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "registration.h"

#include <objbase.h>
#include <strsafe.h>
#include <wchar.h>

static HRESULT fx_reg_set_string(HKEY root, PCWSTR subkey, PCWSTR value_name, PCWSTR value)
{
	HRESULT hr = E_FAIL;
	HKEY key = NULL;
	LONG status;
	DWORD disposition;
	size_t bytes;

	status = RegCreateKeyExW(root, subkey, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_WRITE, NULL, &key, &disposition);
	if (status != ERROR_SUCCESS)
	{
		hr = HRESULT_FROM_WIN32(status);
		goto fail;
	}

	bytes = (wcslen(value) + 1U) * sizeof(WCHAR);
	if (bytes > 0xffffffffUL)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	status = RegSetValueExW(key, value_name, 0, REG_SZ, (const BYTE *)value, (DWORD)bytes);
	if (status != ERROR_SUCCESS)
	{
		hr = HRESULT_FROM_WIN32(status);
		goto fail;
	}

	hr = S_OK;

fail:
	if (key)
		RegCloseKey(key);

	return hr;
}

static HRESULT fx_reg_delete_tree(HKEY root, PCWSTR subkey)
{
	LONG status = RegDeleteTreeW(root, subkey);

	if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND)
		return S_OK;

	return HRESULT_FROM_WIN32(status);
}

HRESULT fx_register_server(const CLSID *clsid, PCWSTR module_path)
{
	HRESULT hr;
	WCHAR clsid_text[64];
	WCHAR subkey[256];

	if (StringFromGUID2(clsid, clsid_text, ARRAYSIZE(clsid_text)) == 0)
		return E_FAIL;

	hr = StringCchPrintfW(subkey, ARRAYSIZE(subkey), L"CLSID\\%s", clsid_text);
	if (FAILED(hr))
		goto fail;
	hr = fx_reg_set_string(HKEY_CLASSES_ROOT, subkey, NULL, L"FileXRay Property Sheet Handler");
	if (FAILED(hr))
		goto fail;

	hr = StringCchPrintfW(subkey, ARRAYSIZE(subkey), L"CLSID\\%s\\InprocServer32", clsid_text);
	if (FAILED(hr))
		goto fail;
	hr = fx_reg_set_string(HKEY_CLASSES_ROOT, subkey, NULL, module_path);
	if (FAILED(hr))
		goto fail;
	hr = fx_reg_set_string(HKEY_CLASSES_ROOT, subkey, L"ThreadingModel", L"Apartment");
	if (FAILED(hr))
		goto fail;

	hr = fx_reg_set_string(HKEY_CLASSES_ROOT,
		L"AllFilesystemObjects\\ShellEx\\PropertySheetHandlers\\FileXRay", NULL, clsid_text);

fail:
	return hr;
}

HRESULT fx_unregister_server(const CLSID *clsid)
{
	HRESULT hr;
	WCHAR clsid_text[64];
	WCHAR subkey[256];

	if (StringFromGUID2(clsid, clsid_text, ARRAYSIZE(clsid_text)) == 0)
		return E_FAIL;

	hr = fx_reg_delete_tree(HKEY_CLASSES_ROOT, L"AllFilesystemObjects\\ShellEx\\PropertySheetHandlers\\FileXRay");
	if (FAILED(hr))
		goto fail;

	hr = StringCchPrintfW(subkey, ARRAYSIZE(subkey), L"CLSID\\%s", clsid_text);
	if (FAILED(hr))
		goto fail;
	hr = fx_reg_delete_tree(HKEY_CLASSES_ROOT, subkey);

fail:
	return hr;
}
