/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "extensions.h"
#include "../pe.h"

#include <commctrl.h>
#include <stddef.h>
#include <string.h>
#include <strsafe.h>

#define FX_DLL_ID_EXPORTS 3101
#define FX_DLL_MAX_EXPORT_ENTRIES 65536U
#define FX_DLL_MAX_NAME_LENGTH 32767U
#define FX_DLL_NO_NAME MAXDWORD

typedef struct FX_DLL_VIEW
{
	HWND parent;
	HWND exports;
} FX_DLL_VIEW;

static HRESULT fx_dll_copy_export_name(const FX_PE_IMAGE *image, DWORD rva,
	WCHAR **name)
{
	const char *source;
	const char *terminator;
	size_t available;
	size_t length;
	size_t index;
	HRESULT hr;

	*name = NULL;
	hr = fx_pe_rva_to_pointer(image, rva, 1, (const void **)&source,
		&available);
	if (FAILED(hr))
		return hr;

	terminator = (const char *)memchr(source, '\0', available);
	if (!terminator)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	length = (size_t)(terminator - source);
	if (length > FX_DLL_MAX_NAME_LENGTH)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	*name = (WCHAR *)HeapAlloc(GetProcessHeap(), 0,
		(length + 1U) * sizeof(WCHAR));
	if (!*name)
		return E_OUTOFMEMORY;

	for (index = 0; index < length; index++)
		(*name)[index] = (WCHAR)(BYTE)source[index];
	(*name)[length] = L'\0';
	return S_OK;
}

static HRESULT fx_dll_set_item_text(HWND list, int row, int column,
	PWSTR text)
{
	LVITEMW item;

	ZeroMemory(&item, sizeof(item));
	item.iSubItem = column;
	item.pszText = text;
	if (!SendMessageW(list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&item))
		return E_FAIL;
	return S_OK;
}

static HRESULT fx_dll_insert_export(FX_DLL_VIEW *view, int row, DWORD rva,
	PCWSTR name, DWORD ordinal, BOOL has_hint, DWORD hint)
{
	WCHAR rva_text[16];
	WCHAR ordinal_text[16];
	WCHAR hint_text[16];
	LVITEMW item;
	HRESULT hr;

	hr = StringCchPrintfW(rva_text, ARRAYSIZE(rva_text), L"0x%08lX",
		(unsigned long)rva);
	if (FAILED(hr))
		return hr;
	hr = StringCchPrintfW(ordinal_text, ARRAYSIZE(ordinal_text), L"%lu",
		(unsigned long)ordinal);
	if (FAILED(hr))
		return hr;

	hint_text[0] = L'\0';
	if (has_hint)
	{
		hr = StringCchPrintfW(hint_text, ARRAYSIZE(hint_text), L"%lu",
			(unsigned long)hint);
		if (FAILED(hr))
			return hr;
	}

	ZeroMemory(&item, sizeof(item));
	item.mask = LVIF_TEXT;
	item.iItem = row;
	item.pszText = rva_text;
	if (SendMessageW(view->exports, LVM_INSERTITEMW, 0, (LPARAM)&item) == -1)
		return E_OUTOFMEMORY;

	hr = fx_dll_set_item_text(view->exports, row, 1, (PWSTR)name);
	if (FAILED(hr))
		return hr;
	hr = fx_dll_set_item_text(view->exports, row, 2, ordinal_text);
	if (FAILED(hr))
		return hr;
	return fx_dll_set_item_text(view->exports, row, 3, hint_text);
}

static HRESULT fx_dll_populate(FX_DLL_VIEW *view, const FX_PE_IMAGE *image)
{
	IMAGE_DATA_DIRECTORY export_dir;
	const IMAGE_EXPORT_DIRECTORY *directory;
	const DWORD *function_rvas;
	const DWORD *name_rvas = NULL;
	const WORD *name_ordinals = NULL;
	DWORD *name_heads = NULL;
	DWORD *name_next = NULL;
	WCHAR *name = NULL;
	DWORD function_index;
	DWORD name_index;
	DWORD row_count;
	int row = 0;
	HRESULT hr;

	hr = fx_pe_get_data_directory(image, IMAGE_DIRECTORY_ENTRY_EXPORT,
		&export_dir);
	if (FAILED(hr))
		goto fail;
	if (hr == S_FALSE || export_dir.VirtualAddress == 0)
	{
		hr = S_OK;
		goto fail;
	}
	if (export_dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	hr = fx_pe_rva_to_pointer(image, export_dir.VirtualAddress,
		sizeof(*directory), (const void **)&directory, NULL);
	if (FAILED(hr))
		goto fail;

	if (directory->NumberOfFunctions > FX_DLL_MAX_EXPORT_ENTRIES ||
		directory->NumberOfNames > FX_DLL_MAX_EXPORT_ENTRIES ||
		(directory->NumberOfNames > 0 && directory->NumberOfFunctions == 0))
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	if (directory->NumberOfFunctions == 0)
	{
		hr = S_OK;
		goto fail;
	}

	hr = fx_pe_rva_to_pointer(image, directory->AddressOfFunctions,
		(size_t)directory->NumberOfFunctions * sizeof(*function_rvas),
		(const void **)&function_rvas, NULL);
	if (FAILED(hr))
		goto fail;

	name_heads = (DWORD *)HeapAlloc(GetProcessHeap(), 0,
		(size_t)directory->NumberOfFunctions * sizeof(*name_heads));
	if (!name_heads)
	{
		hr = E_OUTOFMEMORY;
		goto fail;
	}
	FillMemory(name_heads,
		(size_t)directory->NumberOfFunctions * sizeof(*name_heads), 0xFF);

	if (directory->NumberOfNames > 0)
	{
		hr = fx_pe_rva_to_pointer(image, directory->AddressOfNames,
			(size_t)directory->NumberOfNames * sizeof(*name_rvas),
			(const void **)&name_rvas, NULL);
		if (FAILED(hr))
			goto fail;
		hr = fx_pe_rva_to_pointer(image, directory->AddressOfNameOrdinals,
			(size_t)directory->NumberOfNames * sizeof(*name_ordinals),
			(const void **)&name_ordinals, NULL);
		if (FAILED(hr))
			goto fail;

		name_next = (DWORD *)HeapAlloc(GetProcessHeap(), 0,
			(size_t)directory->NumberOfNames * sizeof(*name_next));
		if (!name_next)
		{
			hr = E_OUTOFMEMORY;
			goto fail;
		}

		for (name_index = directory->NumberOfNames; name_index > 0;
			name_index--)
		{
			DWORD current = name_index - 1U;
			WORD ordinal_index = name_ordinals[current];

			if ((DWORD)ordinal_index >= directory->NumberOfFunctions)
			{
				hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
				goto fail;
			}
			name_next[current] = name_heads[ordinal_index];
			name_heads[ordinal_index] = current;
		}
	}

	row_count = directory->NumberOfNames;
	for (function_index = 0;
		function_index < directory->NumberOfFunctions; function_index++)
	{
		if (function_rvas[function_index] == 0)
		{
			if (name_heads[function_index] != FX_DLL_NO_NAME)
			{
				hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
				goto fail;
			}
			continue;
		}
		if (name_heads[function_index] == FX_DLL_NO_NAME)
			row_count++;
	}
	if (row_count > FX_DLL_MAX_EXPORT_ENTRIES)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	SendMessageW(view->exports, WM_SETREDRAW, FALSE, 0);
	for (function_index = 0;
		function_index < directory->NumberOfFunctions; function_index++)
	{
		ULONGLONG ordinal_value;

		if (function_rvas[function_index] == 0)
			continue;

		ordinal_value = (ULONGLONG)directory->Base + function_index;
		if (ordinal_value > MAXDWORD)
		{
			hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
			goto fail;
		}

		name_index = name_heads[function_index];
		if (name_index == FX_DLL_NO_NAME)
		{
			hr = fx_dll_insert_export(view, row, function_rvas[function_index],
				L"", (DWORD)ordinal_value, FALSE, 0);
			if (FAILED(hr))
				goto fail;
			row++;
			continue;
		}

		while (name_index != FX_DLL_NO_NAME)
		{
			hr = fx_dll_copy_export_name(image, name_rvas[name_index], &name);
			if (FAILED(hr))
				goto fail;

			hr = fx_dll_insert_export(view, row, function_rvas[function_index],
				name, (DWORD)ordinal_value, TRUE, name_index);
			HeapFree(GetProcessHeap(), 0, name);
			name = NULL;
			if (FAILED(hr))
				goto fail;

			row++;
			name_index = name_next[name_index];
		}
	}
	hr = S_OK;

fail:
	SendMessageW(view->exports, WM_SETREDRAW, TRUE, 0);
	InvalidateRect(view->exports, NULL, TRUE);
	if (name)
		HeapFree(GetProcessHeap(), 0, name);
	if (name_next)
		HeapFree(GetProcessHeap(), 0, name_next);
	if (name_heads)
		HeapFree(GetProcessHeap(), 0, name_heads);
	return hr;
}

static HRESULT fx_dll_load(PCWSTR path, FX_DLL_VIEW *view)
{
	FX_PE_IMAGE image;
	HRESULT hr;

	hr = fx_pe_open(path, &image);
	if (FAILED(hr))
		return hr;

	hr = fx_dll_populate(view, &image);
	fx_pe_close(&image);
	return hr;
}

static HRESULT fx_dll_add_column(HWND list, int index, PCWSTR text, int format)
{
	LVCOLUMNW column;

	ZeroMemory(&column, sizeof(column));
	column.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH;
	column.fmt = format;
	column.cx = 1;
	column.pszText = (PWSTR)text;
	if (SendMessageW(list, LVM_INSERTCOLUMNW, (WPARAM)index,
		(LPARAM)&column) == -1)
		return E_FAIL;
	return S_OK;
}

static void fx_dll_destroy(void *context)
{
	FX_DLL_VIEW *view = (FX_DLL_VIEW *)context;

	if (view->exports)
		DestroyWindow(view->exports);
	HeapFree(GetProcessHeap(), 0, view);
}

static HRESULT fx_dll_create(HWND parent, PCWSTR path, void **context)
{
	FX_DLL_VIEW *view;
	INITCOMMONCONTROLSEX common_controls;
	HINSTANCE instance;
	HFONT font;
	DWORD error;
	HRESULT hr;

	*context = NULL;
	view = (FX_DLL_VIEW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		sizeof(*view));
	if (!view)
		return E_OUTOFMEMORY;
	view->parent = parent;

	common_controls.dwSize = sizeof(common_controls);
	common_controls.dwICC = ICC_LISTVIEW_CLASSES;
	if (!InitCommonControlsEx(&common_controls))
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_GEN_FAILURE;
		hr = HRESULT_FROM_WIN32(error);
		goto fail;
	}

	instance = (HINSTANCE)(ULONG_PTR)GetWindowLongPtrW(parent, GWLP_HINSTANCE);
	view->exports = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
			LVS_SHOWSELALWAYS,
		0, 0, 0, 0, parent, (HMENU)(UINT_PTR)FX_DLL_ID_EXPORTS, instance, NULL);
	if (!view->exports)
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_NOT_ENOUGH_MEMORY;
		hr = HRESULT_FROM_WIN32(error);
		goto fail;
	}

	font = (HFONT)SendMessageW(parent, WM_GETFONT, 0, 0);
	if (font)
		SendMessageW(view->exports, WM_SETFONT, (WPARAM)font, FALSE);
	SendMessageW(view->exports, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
			LVS_EX_LABELTIP);

	hr = fx_dll_add_column(view->exports, 0, L"RVA", LVCFMT_LEFT);
	if (FAILED(hr))
		goto fail;
	hr = fx_dll_add_column(view->exports, 1, L"Name", LVCFMT_LEFT);
	if (FAILED(hr))
		goto fail;
	hr = fx_dll_add_column(view->exports, 2, L"Ordinal", LVCFMT_RIGHT);
	if (FAILED(hr))
		goto fail;
	hr = fx_dll_add_column(view->exports, 3, L"Hint", LVCFMT_RIGHT);
	if (FAILED(hr))
		goto fail;

	hr = fx_dll_load(path, view);
	if (FAILED(hr))
		goto fail;

	*context = view;
	return S_OK;

fail:
	fx_dll_destroy(view);
	return hr;
}

static int fx_dll_dlg_x(HWND hwnd, int value)
{
	RECT rect = { 0, 0, value, 0 };

	MapDialogRect(hwnd, &rect);
	return rect.right;
}

static void fx_dll_layout(void *context, const RECT *bounds)
{
	FX_DLL_VIEW *view = (FX_DLL_VIEW *)context;
	RECT client;
	int rva_width;
	int ordinal_width;
	int hint_width;
	int name_width;
	int width;
	int height;

	width = bounds->right - bounds->left;
	height = bounds->bottom - bounds->top;
	MoveWindow(view->exports, bounds->left, bounds->top, width, height, TRUE);

	GetClientRect(view->exports, &client);
	width = client.right - client.left;
	rva_width = fx_dll_dlg_x(view->parent, 55);
	ordinal_width = fx_dll_dlg_x(view->parent, 44);
	hint_width = fx_dll_dlg_x(view->parent, 36);
	name_width = width - rva_width - ordinal_width - hint_width;
	if (name_width < fx_dll_dlg_x(view->parent, 40))
		name_width = fx_dll_dlg_x(view->parent, 40);

	SendMessageW(view->exports, LVM_SETCOLUMNWIDTH, 0, rva_width);
	SendMessageW(view->exports, LVM_SETCOLUMNWIDTH, 1, name_width);
	SendMessageW(view->exports, LVM_SETCOLUMNWIDTH, 2, ordinal_width);
	SendMessageW(view->exports, LVM_SETCOLUMNWIDTH, 3, hint_width);
}

const FX_EXTENSION_HANDLER fx_extension_dll_handler =
{
	L".dll",
	L"Exports",
	fx_dll_create,
	fx_dll_layout,
	fx_dll_destroy,
	NULL
};
