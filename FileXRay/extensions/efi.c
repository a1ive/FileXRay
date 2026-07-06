/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "extensions.h"

#include <stddef.h>
#include <string.h>
#include <strsafe.h>

#define FX_EFI_ID_BASE_LABEL 3001
#define FX_EFI_ID_BASE_VALUE 3002
#define FX_EFI_ID_SBAT_LABEL 3003
#define FX_EFI_ID_SBAT_VALUE 3004

typedef struct FX_EFI_VIEW
{
	HWND parent;
	HWND base_label;
	HWND base_value;
	HWND sbat_label;
	HWND sbat_value;
	WCHAR base_address[32];
	WCHAR *sbat;
} FX_EFI_VIEW;

static HRESULT fx_efi_format_image_base(const IMAGE_NT_HEADERS *nt, WCHAR *text, size_t cch)
{
	if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt;

		return StringCchPrintfW(text, cch, L"0x%016llX",
			(unsigned long long)nt64->OptionalHeader.ImageBase);
	}
	else
	{
		const IMAGE_NT_HEADERS32 *nt32 = (const IMAGE_NT_HEADERS32 *)nt;

		return StringCchPrintfW(text, cch, L"0x%08lX",
			(unsigned long)nt32->OptionalHeader.ImageBase);
	}
}

static HRESULT fx_efi_find_section(const IMAGE_NT_HEADERS *nt, const void *base,
	size_t file_size, const char *name, const IMAGE_SECTION_HEADER **section)
{
	const IMAGE_SECTION_HEADER *sections;
	size_t optional_offset;
	size_t sections_offset;
	WORD count;
	WORD index;

	*section = NULL;
	optional_offset = (const BYTE *)&nt->OptionalHeader - (const BYTE *)base;
	if (optional_offset > file_size ||
		(size_t)nt->FileHeader.SizeOfOptionalHeader > file_size - optional_offset)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	sections_offset = optional_offset + nt->FileHeader.SizeOfOptionalHeader;
	count = nt->FileHeader.NumberOfSections;
	if ((size_t)count > (file_size - sections_offset) / sizeof(IMAGE_SECTION_HEADER))
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	sections = (const IMAGE_SECTION_HEADER *)((const BYTE *)base + sections_offset);
	for (index = 0; index < count; index++)
	{
		if (memcmp(sections[index].Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
		{
			*section = &sections[index];
			break;
		}
	}

	return S_OK;
}

static HRESULT fx_efi_convert_sbat(const char *data, DWORD length, WCHAR **text)
{
	WCHAR *raw = NULL;
	WCHAR *normalized = NULL;
	size_t extra = 0;
	size_t source;
	size_t target;
	int converted;
	HRESULT hr;

	*text = NULL;
	converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, (int)length,
		NULL, 0);
	if (converted <= 0)
		return HRESULT_FROM_WIN32(GetLastError());

	raw = (WCHAR *)HeapAlloc(GetProcessHeap(), 0,
		((size_t)converted + 1U) * sizeof(WCHAR));
	if (!raw)
		return E_OUTOFMEMORY;

	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, (int)length, raw,
		converted) != converted)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}
	raw[converted] = L'\0';

	for (source = 0; source < (size_t)converted; source++)
	{
		if (raw[source] == L'\n' && (source == 0 || raw[source - 1U] != L'\r'))
			extra++;
	}

	if (extra == 0)
	{
		*text = raw;
		return S_OK;
	}

	normalized = (WCHAR *)HeapAlloc(GetProcessHeap(), 0,
		((size_t)converted + extra + 1U) * sizeof(WCHAR));
	if (!normalized)
	{
		hr = E_OUTOFMEMORY;
		goto fail;
	}

	target = 0;
	for (source = 0; source < (size_t)converted; source++)
	{
		if (raw[source] == L'\n' && (source == 0 || raw[source - 1U] != L'\r'))
			normalized[target++] = L'\r';
		normalized[target++] = raw[source];
	}
	normalized[target] = L'\0';

	HeapFree(GetProcessHeap(), 0, raw);
	*text = normalized;
	return S_OK;

fail:
	if (normalized)
		HeapFree(GetProcessHeap(), 0, normalized);
	if (raw)
		HeapFree(GetProcessHeap(), 0, raw);
	return hr;
}

static HRESULT fx_efi_read_sbat(const void *base, size_t file_size,
	const IMAGE_NT_HEADERS *nt, WCHAR **text)
{
	const IMAGE_SECTION_HEADER *sbat;
	const char *sbat_data;
	DWORD actual_length;
	char name[IMAGE_SIZEOF_SHORT_NAME];
	HRESULT hr;

	*text = NULL;
	ZeroMemory(name, sizeof(name));
	CopyMemory(name, ".sbat", 5);

	hr = fx_efi_find_section(nt, base, file_size, name, &sbat);
	if (FAILED(hr) || !sbat)
		return hr;

	if (sbat->PointerToRawData == 0 || sbat->SizeOfRawData == 0)
		return S_OK;
	if ((size_t)sbat->PointerToRawData > file_size ||
		(size_t)sbat->SizeOfRawData > file_size - sbat->PointerToRawData)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	sbat_data = (const char *)base + sbat->PointerToRawData;
	actual_length = sbat->SizeOfRawData;
	while (actual_length > 0 && sbat_data[actual_length - 1U] == '\0')
		actual_length--;

	if (actual_length == 0)
		return S_OK;

	return fx_efi_convert_sbat(sbat_data, actual_length, text);
}

static HRESULT fx_efi_load(PCWSTR path, FX_EFI_VIEW *view)
{
	HANDLE file = INVALID_HANDLE_VALUE;
	HANDLE mapping = NULL;
	const void *mapping_view = NULL;
	const IMAGE_DOS_HEADER *dos;
	const IMAGE_NT_HEADERS *nt;
	LARGE_INTEGER file_size_value;
	size_t file_size;
	size_t nt_offset;
	size_t optional_offset;
	size_t image_base_end;
	HRESULT hr;

	file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	if (!GetFileSizeEx(file, &file_size_value) || file_size_value.QuadPart == 0)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}
	if (file_size_value.QuadPart > (LONGLONG)(256ULL * 1024ULL * 1024ULL))
	{
		hr = HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
		goto fail;
	}
	file_size = (size_t)file_size_value.QuadPart;

	mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!mapping)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	mapping_view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (!mapping_view)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	if (file_size < sizeof(IMAGE_DOS_HEADER))
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	dos = (const IMAGE_DOS_HEADER *)mapping_view;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	nt_offset = (size_t)dos->e_lfanew;
	if (nt_offset > file_size ||
		offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + sizeof(WORD) >
			file_size - nt_offset)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	nt = (const IMAGE_NT_HEADERS *)((const BYTE *)mapping_view + nt_offset);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	optional_offset = nt_offset + offsetof(IMAGE_NT_HEADERS32, OptionalHeader);
	if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		image_base_end = offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase) + sizeof(ULONGLONG);
	else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		image_base_end = offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase) + sizeof(DWORD);
	else
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	if ((size_t)nt->FileHeader.SizeOfOptionalHeader < image_base_end ||
		optional_offset > file_size || image_base_end > file_size - optional_offset)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}

	hr = fx_efi_format_image_base(nt, view->base_address,
		ARRAYSIZE(view->base_address));
	if (FAILED(hr))
		goto fail;

	hr = fx_efi_read_sbat(mapping_view, file_size, nt, &view->sbat);

fail:
	if (mapping_view)
		UnmapViewOfFile(mapping_view);
	if (mapping)
		CloseHandle(mapping);
	if (file != INVALID_HANDLE_VALUE)
		CloseHandle(file);
	return hr;
}

static HRESULT fx_efi_create_control(FX_EFI_VIEW *view, HWND *control, DWORD ex_style,
	PCWSTR class_name, PCWSTR text, DWORD style, int id)
{
	HINSTANCE instance;
	HFONT font;
	DWORD error;

	instance = (HINSTANCE)(ULONG_PTR)GetWindowLongPtrW(view->parent, GWLP_HINSTANCE);
	*control = CreateWindowExW(ex_style, class_name, text, style | WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, view->parent, (HMENU)(UINT_PTR)id, instance, NULL);
	if (!*control)
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_NOT_ENOUGH_MEMORY;
		return HRESULT_FROM_WIN32(error);
	}

	font = (HFONT)SendMessageW(view->parent, WM_GETFONT, 0, 0);
	if (font)
		SendMessageW(*control, WM_SETFONT, (WPARAM)font, FALSE);

	return S_OK;
}

static void fx_efi_destroy(void *context)
{
	FX_EFI_VIEW *view = (FX_EFI_VIEW *)context;

	if (view->sbat_value)
		DestroyWindow(view->sbat_value);
	if (view->sbat_label)
		DestroyWindow(view->sbat_label);
	if (view->base_value)
		DestroyWindow(view->base_value);
	if (view->base_label)
		DestroyWindow(view->base_label);
	if (view->sbat)
		HeapFree(GetProcessHeap(), 0, view->sbat);
	HeapFree(GetProcessHeap(), 0, view);
}

static HRESULT fx_efi_create(HWND parent, PCWSTR path, void **context)
{
	FX_EFI_VIEW *view;
	HRESULT hr;

	*context = NULL;
	view = (FX_EFI_VIEW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*view));
	if (!view)
		return E_OUTOFMEMORY;
	view->parent = parent;

	hr = fx_efi_load(path, view);
	if (FAILED(hr))
		goto fail;

	hr = fx_efi_create_control(view, &view->base_label, 0, L"STATIC",
		L"Base Address", SS_LEFT, FX_EFI_ID_BASE_LABEL);
	if (FAILED(hr))
		goto fail;
	hr = fx_efi_create_control(view, &view->base_value, WS_EX_CLIENTEDGE, L"EDIT",
		view->base_address, WS_TABSTOP | ES_AUTOHSCROLL | ES_READONLY,
		FX_EFI_ID_BASE_VALUE);
	if (FAILED(hr))
		goto fail;

	if (view->sbat)
	{
		hr = fx_efi_create_control(view, &view->sbat_label, 0, L"STATIC", L"SBAT",
			SS_LEFT, FX_EFI_ID_SBAT_LABEL);
		if (FAILED(hr))
			goto fail;
		hr = fx_efi_create_control(view, &view->sbat_value, WS_EX_CLIENTEDGE, L"EDIT",
			view->sbat, WS_TABSTOP | WS_HSCROLL | WS_VSCROLL | ES_AUTOHSCROLL |
			ES_AUTOVSCROLL | ES_MULTILINE | ES_READONLY,
			FX_EFI_ID_SBAT_VALUE);
		if (FAILED(hr))
			goto fail;
	}

	*context = view;
	return S_OK;

fail:
	fx_efi_destroy(view);
	return hr;
}

static int fx_efi_dlg_x(HWND hwnd, int value)
{
	RECT rect = { 0, 0, value, 0 };

	MapDialogRect(hwnd, &rect);
	return rect.right;
}

static int fx_efi_dlg_y(HWND hwnd, int value)
{
	RECT rect = { 0, 0, 0, value };

	MapDialogRect(hwnd, &rect);
	return rect.bottom;
}

static void fx_efi_layout(void *context, const RECT *bounds)
{
	FX_EFI_VIEW *view = (FX_EFI_VIEW *)context;
	int label_width;
	int label_height;
	int edit_height;
	int horizontal_gap;
	int section_gap;
	int sbat_gap;
	int value_x;
	int width;
	int base_label_y;
	int sbat_label_y;
	int sbat_value_y;
	int sbat_height;

	label_width = fx_efi_dlg_x(view->parent, 62);
	label_height = fx_efi_dlg_y(view->parent, 8);
	edit_height = fx_efi_dlg_y(view->parent, 14);
	horizontal_gap = fx_efi_dlg_x(view->parent, 5);
	section_gap = fx_efi_dlg_y(view->parent, 6);
	sbat_gap = fx_efi_dlg_y(view->parent, 2);

	width = bounds->right - bounds->left;
	value_x = bounds->left + label_width + horizontal_gap;
	base_label_y = bounds->top + (edit_height - label_height) / 2;
	sbat_label_y = bounds->top + edit_height + section_gap;
	sbat_value_y = sbat_label_y + label_height + sbat_gap;
	sbat_height = bounds->bottom - sbat_value_y;
	if (sbat_height < edit_height)
		sbat_height = edit_height;

	MoveWindow(view->base_label, bounds->left, base_label_y, label_width, label_height,
		TRUE);
	MoveWindow(view->base_value, value_x, bounds->top,
		bounds->right - value_x, edit_height, TRUE);

	if (!view->sbat)
		return;

	MoveWindow(view->sbat_label, bounds->left, sbat_label_y, width, label_height, TRUE);
	MoveWindow(view->sbat_value, bounds->left, sbat_value_y, width, sbat_height, TRUE);
}

const FX_EXTENSION_HANDLER fx_extension_efi_handler =
{
	L".efi",
	L"EFI",
	fx_efi_create,
	fx_efi_layout,
	fx_efi_destroy,
	NULL
};
