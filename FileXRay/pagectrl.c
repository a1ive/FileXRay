/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "pagectrl.h"

#include <pathcch.h>
#include <strsafe.h>
#include <wchar.h>

#include "filetype.h"
#include "hash.h"
#include "resource.h"

#define FXM_HASH_PROGRESS (WM_APP + 40)
#define FXM_HASH_COMPLETE (WM_APP + 41)

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

#ifndef WM_DPICHANGED_AFTERPARENT
#define WM_DPICHANGED_AFTERPARENT 0x02E3
#endif

#define FX_DEFAULT_DPI 96U

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

typedef struct FX_PAGE_STATE
{
	LONG ref_count;
	HINSTANCE instance;
	HWND hwnd;
	WCHAR *path;
	volatile LONG cancel;
	volatile LONG running;
	UINT dpi;
	HFONT font;
	DWORD hash_mask;
	HRESULT hash_hr;
	FX_HASH_RESULT hash_result;
	WCHAR hash_text[1024];
	WCHAR title[64];
} FX_PAGE_STATE;

typedef UINT (WINAPI *FX_GET_DPI_FOR_WINDOW)(HWND hwnd);

typedef struct FX_HASH_TEXT_ITEM
{
	DWORD mask;
	PCWSTR name;
	PCWSTR value;
} FX_HASH_TEXT_ITEM;

typedef struct FX_EXTENSION_RULE
{
	PCWSTR extension;
	UINT string_id;
} FX_EXTENSION_RULE;

static void fx_load_string_value(HINSTANCE instance, UINT id, WCHAR *buffer, size_t cch_buffer)
{
	int length;

	if (cch_buffer == 0)
		return;

	length = LoadStringW(instance, id, buffer, (int)cch_buffer);
	if (length == 0)
		buffer[0] = L'\0';
}

static void fx_set_dlg_item_text_id(HWND hwnd, HINSTANCE instance, int item_id, UINT string_id)
{
	WCHAR text[256];

	fx_load_string_value(instance, string_id, text, ARRAYSIZE(text));
	SetDlgItemTextW(hwnd, item_id, text);
}

static FX_PAGE_STATE *fx_page_state_create(HINSTANCE instance, PCWSTR path)
{
	FX_PAGE_STATE *state = (FX_PAGE_STATE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*state));
	size_t cch;

	if (!state)
		return NULL;

	cch = wcslen(path) + 1U;
	state->path = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, cch * sizeof(WCHAR));
	if (!state->path)
	{
		HeapFree(GetProcessHeap(), 0, state);
		return NULL;
	}
	StringCchCopyW(state->path, cch, path);

	state->ref_count = 1;
	state->instance = instance;
	fx_load_string_value(instance, IDS_PAGE_TITLE, state->title, ARRAYSIZE(state->title));
	if (state->title[0] == L'\0')
		StringCchCopyW(state->title, ARRAYSIZE(state->title), L"FileXRay");

	return state;
}

static void fx_page_state_release(FX_PAGE_STATE *state)
{
	if (InterlockedDecrement(&state->ref_count) == 0)
	{
		if (state->font)
			DeleteObject(state->font);
		if (state->path)
			HeapFree(GetProcessHeap(), 0, state->path);
		HeapFree(GetProcessHeap(), 0, state);
	}
}

static void fx_set_hash_controls_enabled(HWND hwnd, BOOL enabled)
{
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_MD5), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_SHA1), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_CRC32), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_CRC64), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_SHA256), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_START), enabled);
}

static void fx_set_status_from_hresult(HWND hwnd, FX_PAGE_STATE *state, HRESULT hr)
{
	WCHAR format[128];
	WCHAR text[128];

	if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
	{
		fx_set_dlg_item_text_id(hwnd, state->instance, IDC_HASH_STATUS, IDS_HASH_STATUS_CANCELED);
		return;
	}

	fx_load_string_value(state->instance, IDS_HASH_STATUS_FAILED_FORMAT, format, ARRAYSIZE(format));
	if (FAILED(StringCchPrintfW(text, ARRAYSIZE(text), format, (unsigned long)hr)))
		text[0] = L'\0';
	SetDlgItemTextW(hwnd, IDC_HASH_STATUS, text);
}

static HRESULT fx_format_hash_text(FX_PAGE_STATE *state)
{
	const FX_HASH_TEXT_ITEM hash_items[] =
	{
		{ FX_HASH_MD5, L"MD5", state->hash_result.md5 },
		{ FX_HASH_SHA1, L"SHA1", state->hash_result.sha1 },
		{ FX_HASH_CRC32, L"CRC32", state->hash_result.crc32 },
		{ FX_HASH_CRC64, L"CRC64", state->hash_result.crc64 },
		{ FX_HASH_SHA256, L"SHA256", state->hash_result.sha256 }
	};

	HRESULT hr = S_OK;
	DWORD mask = state->hash_result.completed_mask;
	size_t index;

	state->hash_text[0] = L'\0';

	for (index = 0; index < ARRAYSIZE(hash_items); index++)
	{
		if ((mask & hash_items[index].mask) == 0)
			continue;

		hr = StringCchCatW(state->hash_text, ARRAYSIZE(state->hash_text), hash_items[index].name);
		if (FAILED(hr))
			goto fail;
		hr = StringCchCatW(state->hash_text, ARRAYSIZE(state->hash_text), L"\t");
		if (FAILED(hr))
			goto fail;
		hr = StringCchCatW(state->hash_text, ARRAYSIZE(state->hash_text), hash_items[index].value);
		if (FAILED(hr))
			goto fail;
		hr = StringCchCatW(state->hash_text, ARRAYSIZE(state->hash_text), L"\r\n");
		if (FAILED(hr))
			goto fail;
	}

fail:
	return hr;
}

static HRESULT fx_copy_text_to_clipboard(HWND hwnd, PCWSTR text)
{
	HRESULT hr = E_FAIL;
	HGLOBAL memory = NULL;
	void *target;
	size_t cch = wcslen(text) + 1U;
	size_t bytes = cch * sizeof(WCHAR);

	memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
	if (!memory)
	{
		hr = E_OUTOFMEMORY;
		goto fail;
	}

	target = GlobalLock(memory);
	if (!target)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}
	CopyMemory(target, text, bytes);
	GlobalUnlock(memory);

	if (!OpenClipboard(hwnd))
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	EmptyClipboard();
	if (!SetClipboardData(CF_UNICODETEXT, memory))
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		CloseClipboard();
		goto fail;
	}

	memory = NULL;
	CloseClipboard();
	hr = S_OK;

fail:
	if (memory)
		GlobalFree(memory);

	return hr;
}

static BOOL CALLBACK fx_hash_progress(ULONGLONG bytes_done, ULONGLONG bytes_total, void *context)
{
	FX_PAGE_STATE *state = (FX_PAGE_STATE *)context;
	DWORD percent;
	HWND hwnd;

	if (InterlockedCompareExchange(&state->cancel, 0, 0) != 0)
		return FALSE;

	if (bytes_total == 0)
		percent = 100;
	else
		percent = (DWORD)((bytes_done * 100ULL) / bytes_total);
	if (percent > 100)
		percent = 100;

	hwnd = state->hwnd;
	if (hwnd)
		PostMessageW(hwnd, FXM_HASH_PROGRESS, (WPARAM)percent, 0);

	return TRUE;
}

static DWORD WINAPI fx_hash_thread_proc(LPVOID parameter)
{
	FX_PAGE_STATE *state = (FX_PAGE_STATE *)parameter;
	FX_HASH_RESULT result;
	HRESULT hr;
	HWND hwnd;

	hr = fx_hash_file(state->path, state->hash_mask, &state->cancel, &result, fx_hash_progress, state);
	state->hash_result = result;
	state->hash_hr = hr;
	InterlockedExchange(&state->running, 0);

	hwnd = state->hwnd;
	if (hwnd)
		PostMessageW(hwnd, FXM_HASH_COMPLETE, 0, 0);

	fx_page_state_release(state);
	return 0;
}

static void fx_begin_hash(HWND hwnd, FX_PAGE_STATE *state)
{
	DWORD mask = 0;
	HANDLE thread;
	WCHAR text[256];
	WCHAR title[64];

	if (IsDlgButtonChecked(hwnd, IDC_HASH_MD5) == BST_CHECKED)
		mask |= FX_HASH_MD5;
	if (IsDlgButtonChecked(hwnd, IDC_HASH_SHA1) == BST_CHECKED)
		mask |= FX_HASH_SHA1;
	if (IsDlgButtonChecked(hwnd, IDC_HASH_CRC32) == BST_CHECKED)
		mask |= FX_HASH_CRC32;
	if (IsDlgButtonChecked(hwnd, IDC_HASH_CRC64) == BST_CHECKED)
		mask |= FX_HASH_CRC64;
	if (IsDlgButtonChecked(hwnd, IDC_HASH_SHA256) == BST_CHECKED)
		mask |= FX_HASH_SHA256;

	if (mask == 0)
	{
		fx_load_string_value(state->instance, IDS_HASH_SELECT_ONE, text, ARRAYSIZE(text));
		fx_load_string_value(state->instance, IDS_PAGE_TITLE, title, ARRAYSIZE(title));
		MessageBoxW(hwnd, text, title, MB_ICONINFORMATION);
		return;
	}

	if (InterlockedCompareExchange(&state->running, 1, 0) != 0)
		return;

	state->hash_mask = mask;
	state->hash_hr = E_PENDING;
	state->hash_text[0] = L'\0';
	ZeroMemory(&state->hash_result, sizeof(state->hash_result));
	InterlockedExchange(&state->cancel, 0);

	SendDlgItemMessageW(hwnd, IDC_HASH_PROGRESS, PBM_SETPOS, 0, 0);
	SetDlgItemTextW(hwnd, IDC_HASH_RESULT, L"");
	fx_set_dlg_item_text_id(hwnd, state->instance, IDC_HASH_STATUS, IDS_HASH_STATUS_CALCULATING);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_COPY), FALSE);
	fx_set_hash_controls_enabled(hwnd, FALSE);

	InterlockedIncrement(&state->ref_count);
	thread = CreateThread(NULL, 0, fx_hash_thread_proc, state, 0, NULL);
	if (!thread)
	{
		state->hash_hr = HRESULT_FROM_WIN32(GetLastError());
		InterlockedExchange(&state->running, 0);
		fx_page_state_release(state);
		fx_set_status_from_hresult(hwnd, state, state->hash_hr);
		fx_set_hash_controls_enabled(hwnd, TRUE);
		return;
	}

	CloseHandle(thread);
}

static void fx_complete_hash(HWND hwnd, FX_PAGE_STATE *state)
{
	fx_set_hash_controls_enabled(hwnd, TRUE);

	if (SUCCEEDED(state->hash_hr))
	{
		if (SUCCEEDED(fx_format_hash_text(state)))
		{
			SetDlgItemTextW(hwnd, IDC_HASH_RESULT, state->hash_text);
			fx_set_dlg_item_text_id(hwnd, state->instance, IDC_HASH_STATUS, IDS_HASH_STATUS_COMPLETE);
			EnableWindow(GetDlgItem(hwnd, IDC_HASH_COPY), TRUE);
		}
		else
		{
			fx_set_dlg_item_text_id(hwnd, state->instance, IDC_HASH_STATUS, IDS_HASH_STATUS_TOO_LARGE);
			EnableWindow(GetDlgItem(hwnd, IDC_HASH_COPY), FALSE);
		}
	}
	else
	{
		SetDlgItemTextW(hwnd, IDC_HASH_RESULT, L"");
		fx_set_status_from_hresult(hwnd, state, state->hash_hr);
		EnableWindow(GetDlgItem(hwnd, IDC_HASH_COPY), FALSE);
	}
}

static void fx_update_extension(HWND hwnd, FX_PAGE_STATE *state, PCWSTR path)
{
	PCWSTR extension;
	HRESULT hr;

	hr = PathCchFindExtension(path, wcslen(path) + 1U, &extension);
	if (FAILED(hr) || extension[0] == L'\0')
		return;

	SetDlgItemTextW(hwnd, IDC_EXTENSION_GROUP, extension);
}

static UINT fx_get_window_dpi(HWND hwnd)
{
	FX_GET_DPI_FOR_WINDOW get_dpi_for_window = NULL;
	HMODULE user32;
	FARPROC proc;
	HDC hdc;
	int device_dpi;

	user32 = GetModuleHandleW(L"user32.dll");
	if (user32)
	{
		proc = GetProcAddress(user32, "GetDpiForWindow");
		if (proc)
		{
			get_dpi_for_window = (FX_GET_DPI_FOR_WINDOW)proc;
			device_dpi = (int)get_dpi_for_window(hwnd);
			if (device_dpi > 0)
				return (UINT)device_dpi;
		}
	}

	hdc = GetDC(hwnd);
	if (hdc)
	{
		device_dpi = GetDeviceCaps(hdc, LOGPIXELSX);
		ReleaseDC(hwnd, hdc);
		if (device_dpi > 0)
			return (UINT)device_dpi;
	}

	return FX_DEFAULT_DPI;
}

static BOOL CALLBACK fx_set_child_font_proc(HWND hwnd, LPARAM lparam)
{
	SendMessageW(hwnd, WM_SETFONT, (WPARAM)lparam, FALSE);
	return TRUE;
}

static inline int fx_dlg_x(HWND hwnd, int value)
{
	RECT rect = { 0, 0, value, 0 };
	MapDialogRect(hwnd, &rect);
	return rect.right;
}

static inline int fx_dlg_y(HWND hwnd, int value)
{
	RECT rect = { 0, 0, 0, value };
	MapDialogRect(hwnd, &rect);
	return rect.bottom;
}

static inline void fx_move_dlg_item(HWND hwnd, int id, int x, int y, int width, int height)
{
	MoveWindow(GetDlgItem(hwnd, id), x, y, width, height, TRUE);
}

static void fx_layout_dialog(HWND hwnd)
{
	RECT client;
	int client_width;
	int client_height;
	int outer_x;
	int outer_y;
	int field_x;
	int group_width;
	int content_width;
	int file_y;
	int file_height;
	int hash_y;
	int hash_height;
	int extension_y;
	int extension_height;
	int extension_text_y;
	int extension_text_height;
	int checkbox_height;
	int md5_width;
	int sha1_width;
	int crc32_width;
	int crc64_width;
	int sha256_width;
	int hash_column_1;
	int hash_column_2;
	int hash_column_3;
	int button_width;
	int button_height;

	GetClientRect(hwnd, &client);
	client_width = MAX(client.right - client.left, fx_dlg_x(hwnd, 227));
	client_height = MAX(client.bottom - client.top, fx_dlg_y(hwnd, 218));

	outer_x = fx_dlg_x(hwnd, 7);
	outer_y = fx_dlg_y(hwnd, 7);
	field_x = fx_dlg_x(hwnd, 17);
	group_width = MAX(client_width - outer_x * 2, fx_dlg_x(hwnd, 1));
	content_width = MAX(client_width - field_x * 2, fx_dlg_x(hwnd, 1));

	file_y = fx_dlg_y(hwnd, 7);
	file_height = fx_dlg_y(hwnd, 43);
	hash_y = fx_dlg_y(hwnd, 55);
	hash_height = fx_dlg_y(hwnd, 135);
	extension_y = fx_dlg_y(hwnd, 194);
	extension_height = MAX(fx_dlg_y(hwnd, 18), client_height - extension_y - outer_y);
	extension_text_y = fx_dlg_y(hwnd, 203);
	extension_text_height = MAX(fx_dlg_y(hwnd, 10), extension_y + extension_height - fx_dlg_y(hwnd, 6) - extension_text_y);

	checkbox_height = fx_dlg_y(hwnd, 10);
	md5_width = fx_dlg_x(hwnd, 42);
	sha1_width = fx_dlg_x(hwnd, 45);
	crc32_width = fx_dlg_x(hwnd, 52);
	crc64_width = fx_dlg_x(hwnd, 52);
	sha256_width = fx_dlg_x(hwnd, 62);
	hash_column_1 = field_x;
	hash_column_2 = field_x + (content_width - sha1_width) / 2;
	hash_column_3 = client_width - field_x - crc32_width;
	button_width = fx_dlg_x(hwnd, 60);
	button_height = fx_dlg_y(hwnd, 14);

	fx_move_dlg_item(hwnd, IDC_FILE_GROUP, outer_x, file_y, group_width, file_height);
	fx_move_dlg_item(hwnd, IDC_FILE_TYPE, field_x, fx_dlg_y(hwnd, 20), content_width, fx_dlg_y(hwnd, 21));

	fx_move_dlg_item(hwnd, IDC_HASH_GROUP, outer_x, hash_y, group_width, hash_height);
	fx_move_dlg_item(hwnd, IDC_HASH_MD5, hash_column_1, fx_dlg_y(hwnd, 72), md5_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_SHA1, hash_column_2, fx_dlg_y(hwnd, 72), sha1_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_CRC32, hash_column_3, fx_dlg_y(hwnd, 72), crc32_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_CRC64, hash_column_1, fx_dlg_y(hwnd, 86), crc64_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_SHA256, hash_column_2, fx_dlg_y(hwnd, 86), sha256_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_START, field_x, fx_dlg_y(hwnd, 102), button_width, button_height);
	fx_move_dlg_item(hwnd, IDC_HASH_COPY, client_width - field_x - button_width, fx_dlg_y(hwnd, 102), button_width, button_height);
	fx_move_dlg_item(hwnd, IDC_HASH_PROGRESS, field_x, fx_dlg_y(hwnd, 122), content_width, fx_dlg_y(hwnd, 10));
	fx_move_dlg_item(hwnd, IDC_HASH_STATUS, field_x, fx_dlg_y(hwnd, 136), content_width, fx_dlg_y(hwnd, 8));
	fx_move_dlg_item(hwnd, IDC_HASH_RESULT, field_x, fx_dlg_y(hwnd, 148), content_width, fx_dlg_y(hwnd, 34));

	fx_move_dlg_item(hwnd, IDC_EXTENSION_GROUP, outer_x, extension_y, group_width, extension_height);
	fx_move_dlg_item(hwnd, IDC_EXTENSION_TEXT, field_x, extension_text_y, content_width, extension_text_height);
}

static void fx_apply_dialog_dpi(HWND hwnd, FX_PAGE_STATE *state, UINT dpi)
{
	HFONT font;
	HFONT old_font;

	if (dpi == 0)
		dpi = FX_DEFAULT_DPI;

	state->dpi = dpi;
	font = CreateFontW(-MulDiv(9, (int)dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	if (font)
	{
		old_font = state->font;
		state->font = font;
		SendMessageW(hwnd, WM_SETFONT, (WPARAM)font, FALSE);
		EnumChildWindows(hwnd, fx_set_child_font_proc, (LPARAM)font);
		if (old_font)
			DeleteObject(old_font);
	}

	fx_layout_dialog(hwnd);
	InvalidateRect(hwnd, NULL, TRUE);
}

static void fx_initialize_dialog(HWND hwnd, FX_PAGE_STATE *state)
{
	WCHAR format[128];
	WCHAR type_text[512];
	HRESULT hr;

	SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)state);
	state->hwnd = hwnd;

	fx_apply_dialog_dpi(hwnd, state, fx_get_window_dpi(hwnd));

	CheckDlgButton(hwnd, IDC_HASH_SHA256, BST_CHECKED);
	SendDlgItemMessageW(hwnd, IDC_HASH_PROGRESS, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
	SendDlgItemMessageW(hwnd, IDC_HASH_PROGRESS, PBM_SETPOS, 0, 0);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_COPY), FALSE);
	fx_set_dlg_item_text_id(hwnd, state->instance, IDC_HASH_STATUS, IDS_HASH_STATUS_READY);

	hr = fx_filetype_describe_path(state->path, type_text, ARRAYSIZE(type_text));
	if (FAILED(hr))
	{
		fx_load_string_value(state->instance, IDS_FILETYPE_UNABLE_FORMAT, format, ARRAYSIZE(format));
		if (FAILED(StringCchPrintfW(type_text, ARRAYSIZE(type_text), format, (unsigned long)hr)))
			type_text[0] = L'\0';
	}
	SetDlgItemTextW(hwnd, IDC_FILE_TYPE, type_text);

	fx_update_extension(hwnd, state, state->path);
}

static INT_PTR CALLBACK fx_page_dialog_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
	switch (message)
	{
	case WM_INITDIALOG:
	{
		PROPSHEETPAGEW *page = (PROPSHEETPAGEW *)lparam;

		fx_initialize_dialog(hwnd, (FX_PAGE_STATE *)page->lParam);
		return TRUE;
	}
	case WM_SIZE:
		fx_layout_dialog(hwnd);
		return TRUE;
	case WM_DPICHANGED:
	{
		FX_PAGE_STATE* state = (FX_PAGE_STATE*)GetWindowLongPtrW(hwnd, DWLP_USER);
		if (state)
		{
			UINT dpi = LOWORD(wparam);

			if (dpi == 0)
				dpi = HIWORD(wparam);
			if (dpi == 0)
				dpi = FX_DEFAULT_DPI;

			fx_apply_dialog_dpi(hwnd, state, dpi);
		}
		return TRUE;
	}
	case WM_DPICHANGED_AFTERPARENT:
	{
		FX_PAGE_STATE* state = (FX_PAGE_STATE*)GetWindowLongPtrW(hwnd, DWLP_USER);
		if (state)
			fx_apply_dialog_dpi(hwnd, state, fx_get_window_dpi(hwnd));
		return TRUE;
	}
	case WM_COMMAND:
	{
		FX_PAGE_STATE* state = (FX_PAGE_STATE*)GetWindowLongPtrW(hwnd, DWLP_USER);
		if (!state)
			return FALSE;

		switch (LOWORD(wparam))
		{
		case IDC_HASH_START:
			if (HIWORD(wparam) == BN_CLICKED)
				fx_begin_hash(hwnd, state);
			return TRUE;
		case IDC_HASH_COPY:
			if (HIWORD(wparam) == BN_CLICKED && state->hash_text[0] != L'\0')
				fx_copy_text_to_clipboard(hwnd, state->hash_text);
			return TRUE;
		default:
			return FALSE;
		}
	}
	case FXM_HASH_PROGRESS:
		SendDlgItemMessageW(hwnd, IDC_HASH_PROGRESS, PBM_SETPOS, wparam, 0);
		return TRUE;
	case FXM_HASH_COMPLETE:
	{
		FX_PAGE_STATE* state = (FX_PAGE_STATE*)GetWindowLongPtrW(hwnd, DWLP_USER);
		if (state)
			fx_complete_hash(hwnd, state);
		return TRUE;
	}
	case WM_DESTROY:
	{
		FX_PAGE_STATE* state = (FX_PAGE_STATE*)GetWindowLongPtrW(hwnd, DWLP_USER);
		if (state)
		{
			InterlockedExchange(&state->cancel, 1);
			state->hwnd = NULL;
			SetWindowLongPtrW(hwnd, DWLP_USER, 0);
		}
		return TRUE;
	}
	default:
		return FALSE;
	}
}

static UINT CALLBACK fx_page_callback(HWND hwnd, UINT message, LPPROPSHEETPAGEW page)
{
	UNREFERENCED_PARAMETER(hwnd);

	if (message == PSPCB_RELEASE)
		fx_page_state_release((FX_PAGE_STATE *)page->lParam);

	return 1;
}

HRESULT fx_add_property_sheet_page(HINSTANCE instance, PCWSTR path, LPFNADDPROPSHEETPAGE add_page, LPARAM lparam)
{
	PROPSHEETPAGEW page;
	HPROPSHEETPAGE page_handle;
	FX_PAGE_STATE *state;
	INITCOMMONCONTROLSEX common_controls;

	common_controls.dwSize = sizeof(common_controls);
	common_controls.dwICC = ICC_PROGRESS_CLASS;
	InitCommonControlsEx(&common_controls);

	state = fx_page_state_create(instance, path);
	if (!state)
		return E_OUTOFMEMORY;

	ZeroMemory(&page, sizeof(page));
	page.dwSize = sizeof(page);
	page.dwFlags = PSP_USETITLE | PSP_USECALLBACK;
	page.hInstance = instance;
	page.pszTemplate = MAKEINTRESOURCEW(IDD_FILEXRAY_PAGE);
	page.pszTitle = state->title;
	page.pfnDlgProc = fx_page_dialog_proc;
	page.lParam = (LPARAM)state;
	page.pfnCallback = fx_page_callback;

	page_handle = CreatePropertySheetPageW(&page);
	if (!page_handle)
	{
		fx_page_state_release(state);
		return E_FAIL;
	}

	if (!add_page(page_handle, lparam))
	{
		DestroyPropertySheetPage(page_handle);
		return E_FAIL;
	}

	return S_OK;
}
