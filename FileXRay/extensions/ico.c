/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "extensions.h"

#include <commctrl.h>
#include <stddef.h>
#include <string.h>
#include <strsafe.h>

#define FX_ICO_ID_LIST          3301
#define FX_ICO_HEADER_SIZE      6U
#define FX_ICO_ENTRY_SIZE       16U
#define FX_ICO_MAX_IMAGES       4096U
#define FX_ICO_MAX_FILE_SIZE    (256ULL * 1024ULL * 1024ULL)

typedef struct FX_ICO_ENTRY
{
	UINT width;
	UINT height;
	WORD planes;
	WORD bit_count;
	DWORD bytes;
	DWORD offset;
	BOOL is_png;
} FX_ICO_ENTRY;

typedef struct FX_ICO_VIEW
{
	HWND parent;
	HWND list;
	HIMAGELIST images;
	FX_ICO_ENTRY *entries;
	UINT entry_count;
	int preview_size;
} FX_ICO_VIEW;

static WORD fx_ico_read_u16(const BYTE *data)
{
	return (WORD)((WORD)data[0] | ((WORD)data[1] << 8));
}

static DWORD fx_ico_read_u32(const BYTE *data)
{
	return (DWORD)data[0] | ((DWORD)data[1] << 8) |
		((DWORD)data[2] << 16) | ((DWORD)data[3] << 24);
}

static DWORD fx_ico_read_be_u32(const BYTE *data)
{
	return ((DWORD)data[0] << 24) | ((DWORD)data[1] << 16) |
		((DWORD)data[2] << 8) | (DWORD)data[3];
}

static BOOL fx_ico_is_png(const BYTE *data, DWORD size)
{
	static const BYTE png_signature[8] =
	{
		0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A
	};

	return size >= sizeof(png_signature) &&
		memcmp(data, png_signature, sizeof(png_signature)) == 0;
}

static WORD fx_ico_infer_png_bit_count(const BYTE *data, DWORD size)
{
	BYTE bit_depth;
	BYTE color_type;
	BYTE channels;

	if (size < 26 || fx_ico_read_be_u32(data + 8) != 13 ||
		memcmp(data + 12, "IHDR", 4) != 0)
		return 0;

	bit_depth = data[24];
	color_type = data[25];
	switch (color_type)
	{
	case 0:
	case 3:
		channels = 1;
		break;
	case 2:
		channels = 3;
		break;
	case 4:
		channels = 2;
		break;
	case 6:
		channels = 4;
		break;
	default:
		return 0;
	}

	return (WORD)(bit_depth * channels);
}

static WORD fx_ico_infer_dib_bit_count(const BYTE *data, DWORD size)
{
	DWORD header_size;

	if (size < sizeof(DWORD))
		return 0;

	header_size = fx_ico_read_u32(data);
	if (header_size == 12)
	{
		if (size < 12)
			return 0;
		return fx_ico_read_u16(data + 10);
	}
	if (header_size >= 16)
	{
		if (size < 16)
			return 0;
		return fx_ico_read_u16(data + 14);
	}

	return 0;
}

static HRESULT fx_ico_read_file(PCWSTR path, BYTE **data, DWORD *data_size)
{
	HANDLE file = INVALID_HANDLE_VALUE;
	LARGE_INTEGER file_size;
	BYTE *buffer = NULL;
	DWORD bytes_read;
	HRESULT hr;

	*data = NULL;
	*data_size = 0;

	file = CreateFileW(path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return HRESULT_FROM_WIN32(GetLastError());

	if (!GetFileSizeEx(file, &file_size))
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	if (file_size.QuadPart < FX_ICO_HEADER_SIZE)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}
	if (file_size.QuadPart > (LONGLONG)FX_ICO_MAX_FILE_SIZE ||
		file_size.QuadPart > MAXDWORD)
	{
		hr = HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
		goto fail;
	}

	buffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)file_size.QuadPart);
	if (!buffer)
	{
		hr = E_OUTOFMEMORY;
		goto fail;
	}

	if (!ReadFile(file, buffer, (DWORD)file_size.QuadPart, &bytes_read, NULL))
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}
	if (bytes_read != (DWORD)file_size.QuadPart)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	*data = buffer;
	*data_size = bytes_read;
	buffer = NULL;
	hr = S_OK;

fail:
	if (buffer)
		HeapFree(GetProcessHeap(), 0, buffer);
	if (file != INVALID_HANDLE_VALUE)
		CloseHandle(file);
	return hr;
}

static HRESULT fx_ico_parse(const BYTE *data, DWORD data_size,
	FX_ICO_VIEW *view)
{
	FX_ICO_ENTRY *entries = NULL;
	WORD reserved;
	WORD type;
	WORD count;
	UINT index;
	HRESULT hr;

	reserved = fx_ico_read_u16(data);
	type = fx_ico_read_u16(data + 2);
	count = fx_ico_read_u16(data + 4);
	if (reserved != 0 || type != 1 || count == 0)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	if (count > FX_ICO_MAX_IMAGES)
		return HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
	if ((DWORD)count > (data_size - FX_ICO_HEADER_SIZE) / FX_ICO_ENTRY_SIZE)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	entries = (FX_ICO_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		(size_t)count * sizeof(*entries));
	if (!entries)
		return E_OUTOFMEMORY;

	for (index = 0; index < count; index++)
	{
		const BYTE *entry_data = data + FX_ICO_HEADER_SIZE +
			(size_t)index * FX_ICO_ENTRY_SIZE;
		FX_ICO_ENTRY *entry = &entries[index];
		const BYTE *image_data;

		entry->width = entry_data[0] == 0 ? 256U : (UINT)entry_data[0];
		entry->height = entry_data[1] == 0 ? 256U : (UINT)entry_data[1];
		entry->planes = fx_ico_read_u16(entry_data + 4);
		entry->bit_count = fx_ico_read_u16(entry_data + 6);
		entry->bytes = fx_ico_read_u32(entry_data + 8);
		entry->offset = fx_ico_read_u32(entry_data + 12);

		if (entry->bytes == 0 || entry->offset > data_size ||
			entry->bytes > data_size - entry->offset)
		{
			hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
			goto fail;
		}

		image_data = data + entry->offset;
		entry->is_png = fx_ico_is_png(image_data, entry->bytes);
		if (entry->bit_count == 0)
		{
			if (entry->is_png)
				entry->bit_count = fx_ico_infer_png_bit_count(image_data,
					entry->bytes);
			else
				entry->bit_count = fx_ico_infer_dib_bit_count(image_data,
					entry->bytes);
		}
	}

	view->entries = entries;
	view->entry_count = count;
	return S_OK;

fail:
	HeapFree(GetProcessHeap(), 0, entries);
	return hr;
}

static HRESULT fx_ico_add_column(HWND list, int index, PCWSTR text, int format)
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

static HRESULT fx_ico_set_item_text(HWND list, int row, int column,
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

static HRESULT fx_ico_insert_entry(FX_ICO_VIEW *view, UINT index,
	int image_index)
{
	const FX_ICO_ENTRY *entry = &view->entries[index];
	WCHAR number_text[16];
	WCHAR dimensions_text[32];
	WCHAR bit_count_text[32];
	WCHAR bytes_text[32];
	PCWSTR format_text;
	LVITEMW item;
	HRESULT hr;

	hr = StringCchPrintfW(number_text, ARRAYSIZE(number_text), L"%u",
		index + 1U);
	if (FAILED(hr))
		return hr;
	hr = StringCchPrintfW(dimensions_text, ARRAYSIZE(dimensions_text),
		L"%u x %u", entry->width, entry->height);
	if (FAILED(hr))
		return hr;
	if (entry->bit_count == 0)
	{
		hr = StringCchCopyW(bit_count_text, ARRAYSIZE(bit_count_text),
			L"Unknown");
	}
	else
	{
		hr = StringCchPrintfW(bit_count_text, ARRAYSIZE(bit_count_text),
			L"%u-bit", (UINT)entry->bit_count);
	}
	if (FAILED(hr))
		return hr;
	hr = StringCchPrintfW(bytes_text, ARRAYSIZE(bytes_text), L"%lu",
		(unsigned long)entry->bytes);
	if (FAILED(hr))
		return hr;
	format_text = entry->is_png ? L"PNG" : L"DIB";

	ZeroMemory(&item, sizeof(item));
	item.mask = LVIF_TEXT;
	if (image_index >= 0)
	{
		item.mask |= LVIF_IMAGE;
		item.iImage = image_index;
	}
	item.iItem = (int)index;
	item.pszText = number_text;
	if (SendMessageW(view->list, LVM_INSERTITEMW, 0, (LPARAM)&item) == -1)
		return E_OUTOFMEMORY;

	hr = fx_ico_set_item_text(view->list, (int)index, 1, dimensions_text);
	if (FAILED(hr))
		return hr;
	hr = fx_ico_set_item_text(view->list, (int)index, 2, bit_count_text);
	if (FAILED(hr))
		return hr;
	hr = fx_ico_set_item_text(view->list, (int)index, 3, (PWSTR)format_text);
	if (FAILED(hr))
		return hr;
	return fx_ico_set_item_text(view->list, (int)index, 4, bytes_text);
}

static HRESULT fx_ico_populate(FX_ICO_VIEW *view, const BYTE *data)
{
	UINT index;
	DWORD error;

	view->images = ImageList_Create(view->preview_size, view->preview_size,
		ILC_COLOR32 | ILC_MASK, (int)view->entry_count, 1);
	if (!view->images)
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_NOT_ENOUGH_MEMORY;
		return HRESULT_FROM_WIN32(error);
	}

	SendMessageW(view->list, LVM_SETIMAGELIST, LVSIL_SMALL,
		(LPARAM)view->images);
	SendMessageW(view->list, WM_SETREDRAW, FALSE, 0);

	for (index = 0; index < view->entry_count; index++)
	{
		const FX_ICO_ENTRY *entry = &view->entries[index];
		HICON icon;
		int image_index = -1;
		HRESULT hr;

		icon = CreateIconFromResourceEx((PBYTE)(data + entry->offset),
			entry->bytes, TRUE, 0x00030000, view->preview_size,
			view->preview_size, LR_DEFAULTCOLOR);
		if (icon)
		{
			image_index = ImageList_AddIcon(view->images, icon);
			DestroyIcon(icon);
		}

		hr = fx_ico_insert_entry(view, index, image_index);
		if (FAILED(hr))
		{
			SendMessageW(view->list, WM_SETREDRAW, TRUE, 0);
			InvalidateRect(view->list, NULL, TRUE);
			return hr;
		}
	}

	SendMessageW(view->list, WM_SETREDRAW, TRUE, 0);
	InvalidateRect(view->list, NULL, TRUE);
	return S_OK;
}

static HRESULT fx_ico_load(PCWSTR path, FX_ICO_VIEW *view)
{
	BYTE *data = NULL;
	DWORD data_size;
	HRESULT hr;

	hr = fx_ico_read_file(path, &data, &data_size);
	if (FAILED(hr))
		goto fail;

	hr = fx_ico_parse(data, data_size, view);
	if (FAILED(hr))
		goto fail;

	hr = fx_ico_populate(view, data);

fail:
	if (data)
		HeapFree(GetProcessHeap(), 0, data);
	return hr;
}

static void fx_ico_destroy(void *context)
{
	FX_ICO_VIEW *view = (FX_ICO_VIEW *)context;

	if (view->list)
	{
		SendMessageW(view->list, LVM_SETIMAGELIST, LVSIL_SMALL, 0);
		DestroyWindow(view->list);
	}
	if (view->images)
		ImageList_Destroy(view->images);
	if (view->entries)
		HeapFree(GetProcessHeap(), 0, view->entries);
	HeapFree(GetProcessHeap(), 0, view);
}

static int fx_ico_dlg_x(HWND hwnd, int value)
{
	RECT rect = { 0, 0, value, 0 };

	MapDialogRect(hwnd, &rect);
	return rect.right;
}

static int fx_ico_dlg_y(HWND hwnd, int value)
{
	RECT rect = { 0, 0, 0, value };

	MapDialogRect(hwnd, &rect);
	return rect.bottom;
}

static int fx_ico_preview_size(HWND hwnd)
{
	int size = fx_ico_dlg_y(hwnd, 24);

	if (size < 32)
		size = 32;
	if (size > 96)
		size = 96;
	return size;
}

static HRESULT fx_ico_create(HWND parent, PCWSTR path, void **context)
{
	FX_ICO_VIEW *view;
	INITCOMMONCONTROLSEX common_controls;
	HINSTANCE instance;
	HFONT font;
	DWORD error;
	HRESULT hr;

	*context = NULL;
	view = (FX_ICO_VIEW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		sizeof(*view));
	if (!view)
		return E_OUTOFMEMORY;
	view->parent = parent;
	view->preview_size = fx_ico_preview_size(parent);

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
	view->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
			LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS,
		0, 0, 0, 0, parent, (HMENU)(UINT_PTR)FX_ICO_ID_LIST, instance,
		NULL);
	if (!view->list)
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_NOT_ENOUGH_MEMORY;
		hr = HRESULT_FROM_WIN32(error);
		goto fail;
	}

	font = (HFONT)SendMessageW(parent, WM_GETFONT, 0, 0);
	if (font)
		SendMessageW(view->list, WM_SETFONT, (WPARAM)font, FALSE);
	SendMessageW(view->list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
		LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
			LVS_EX_LABELTIP);

	hr = fx_ico_add_column(view->list, 0, L"Preview", LVCFMT_LEFT);
	if (FAILED(hr))
		goto fail;
	hr = fx_ico_add_column(view->list, 1, L"Dimensions", LVCFMT_LEFT);
	if (FAILED(hr))
		goto fail;
	hr = fx_ico_add_column(view->list, 2, L"Depth", LVCFMT_RIGHT);
	if (FAILED(hr))
		goto fail;
	hr = fx_ico_add_column(view->list, 3, L"Format", LVCFMT_LEFT);
	if (FAILED(hr))
		goto fail;
	hr = fx_ico_add_column(view->list, 4, L"Bytes", LVCFMT_RIGHT);
	if (FAILED(hr))
		goto fail;

	hr = fx_ico_load(path, view);
	if (FAILED(hr))
		goto fail;

	*context = view;
	return S_OK;

fail:
	fx_ico_destroy(view);
	return hr;
}

static void fx_ico_layout(void *context, const RECT *bounds)
{
	FX_ICO_VIEW *view = (FX_ICO_VIEW *)context;
	RECT client;
	int width;
	int height;
	int preview_width;
	int dimensions_width;
	int depth_width;
	int format_width;
	int bytes_width;

	width = bounds->right - bounds->left;
	height = bounds->bottom - bounds->top;
	MoveWindow(view->list, bounds->left, bounds->top, width, height, TRUE);

	GetClientRect(view->list, &client);
	width = client.right - client.left;

	preview_width = view->preview_size + fx_ico_dlg_x(view->parent, 28);
	dimensions_width = fx_ico_dlg_x(view->parent, 62);
	depth_width = fx_ico_dlg_x(view->parent, 42);
	format_width = fx_ico_dlg_x(view->parent, 42);
	bytes_width = width - preview_width - dimensions_width - depth_width -
		format_width;
	if (bytes_width < fx_ico_dlg_x(view->parent, 48))
		bytes_width = fx_ico_dlg_x(view->parent, 48);

	SendMessageW(view->list, LVM_SETCOLUMNWIDTH, 0, preview_width);
	SendMessageW(view->list, LVM_SETCOLUMNWIDTH, 1, dimensions_width);
	SendMessageW(view->list, LVM_SETCOLUMNWIDTH, 2, depth_width);
	SendMessageW(view->list, LVM_SETCOLUMNWIDTH, 3, format_width);
	SendMessageW(view->list, LVM_SETCOLUMNWIDTH, 4, bytes_width);
}

const FX_EXTENSION_HANDLER fx_extension_ico_handler =
{
	L".ico",
	L"Icons",
	fx_ico_create,
	fx_ico_layout,
	fx_ico_destroy,
	NULL
};
