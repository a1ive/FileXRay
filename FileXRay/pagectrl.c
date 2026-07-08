/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "pagectrl.h"

#include <pathcch.h>
#include <strsafe.h>
#include <wchar.h>

#include "filetype.h"
#include "hash.h"
#include "resource.h"
#include "extensions/extensions.h"

#define FXM_HASH_PROGRESS (WM_APP + 40)
#define FXM_HASH_COMPLETE (WM_APP + 41)

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

#ifndef WM_DPICHANGED_AFTERPARENT
#define WM_DPICHANGED_AFTERPARENT 0x02E3
#endif

#define FX_DEFAULT_DPI 96U
#define FX_PAGE_TEMPLATE_HEIGHT_DLU 218
#define FX_EXTENSION_Y_DLU 194
#define FX_EXTENSION_MIN_GROUP_HEIGHT_DLU 96
#define FX_PAGE_BOTTOM_MARGIN_DLU 7

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
	HANDLE hash_thread;
	UINT dpi;
	HFONT font;
	BOOL layout_ready;
	BOOL layout_in_progress;
	BOOL scroll_vert_visible;
	int scroll_y;
	int content_height;
	const FX_EXTENSION_HANDLER *extension_handler;
	void *extension_context;
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

static void fx_layout_dialog(HWND hwnd, FX_PAGE_STATE *state);

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

	fx_module_add_ref();
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
		fx_module_release();
	}
}

static void fx_close_hash_thread(FX_PAGE_STATE *state)
{
	if (state->hash_thread)
	{
		CloseHandle(state->hash_thread);
		state->hash_thread = NULL;
	}
}

static void fx_set_hash_controls_enabled(HWND hwnd, BOOL enabled)
{
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_MD5), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_SHA1), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_CRC32), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_CRC64), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_SHA256), enabled);
	EnableWindow(GetDlgItem(hwnd, IDC_HASH_SHA512), enabled);
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
		{ FX_HASH_SHA256, L"SHA256", state->hash_result.sha256 },
		{ FX_HASH_SHA512, L"SHA512", state->hash_result.sha512 }
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
	if (IsDlgButtonChecked(hwnd, IDC_HASH_SHA512) == BST_CHECKED)
		mask |= FX_HASH_SHA512;

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

	state->hash_thread = thread;
}

static void fx_complete_hash(HWND hwnd, FX_PAGE_STATE *state)
{
	fx_close_hash_thread(state);
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

static void fx_destroy_extension(FX_PAGE_STATE *state)
{
	if (!state->extension_handler)
		return;

	state->extension_handler->destroy(state->extension_context);
	state->extension_handler = NULL;
	state->extension_context = NULL;
}

static void fx_update_extension(HWND hwnd, FX_PAGE_STATE *state, PCWSTR path)
{
	const FX_EXTENSION_HANDLER *handler;
	void *context = NULL;
	PCWSTR extension;
	HRESULT hr;

	hr = PathCchFindExtension(path, wcslen(path) + 1U, &extension);
	if (FAILED(hr) || extension[0] == L'\0')
		return;

	handler = fx_extension_find(extension);
	if (!handler)
		return;

	hr = handler->create(hwnd, path, &context);
	if (hr != S_OK)
		return;

	state->extension_handler = handler;
	state->extension_context = context;
	SetDlgItemTextW(hwnd, IDC_EXTENSION_GROUP, handler->title);
	ShowWindow(GetDlgItem(hwnd, IDC_EXTENSION_GROUP), SW_SHOW);
	if (state->layout_ready)
		fx_layout_dialog(hwnd, state);
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

static int fx_clamp_scroll_pos(int position, int content, int page)
{
	int max_scroll;

	max_scroll = content - page;
	if (max_scroll < 0)
		max_scroll = 0;
	if (position < 0)
		return 0;
	if (position > max_scroll)
		return max_scroll;
	return position;
}

static int fx_dialog_min_content_height(HWND hwnd, const FX_PAGE_STATE *state)
{
	int height;

	height = fx_dlg_y(hwnd, FX_PAGE_TEMPLATE_HEIGHT_DLU);
	if (state && state->extension_handler)
	{
		height = MAX(height, fx_dlg_y(hwnd,
			FX_EXTENSION_Y_DLU + FX_EXTENSION_MIN_GROUP_HEIGHT_DLU +
			FX_PAGE_BOTTOM_MARGIN_DLU));
	}

	return height;
}

static BOOL fx_set_dialog_vscroll_visible(HWND hwnd, FX_PAGE_STATE *state, BOOL visible)
{
	LONG_PTR style;
	BOOL style_visible;

	style = GetWindowLongPtrW(hwnd, GWL_STYLE);
	style_visible = (style & WS_VSCROLL) != 0;
	if (state->scroll_vert_visible == visible && style_visible == visible)
		return FALSE;

	if (visible)
		style |= WS_VSCROLL;
	else
		style &= ~WS_VSCROLL;

	SetWindowLongPtrW(hwnd, GWL_STYLE, style);
	state->scroll_vert_visible = visible;
	SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
		SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE |
		SWP_FRAMECHANGED);
	ShowScrollBar(hwnd, SB_VERT, visible);
	return TRUE;
}

static void fx_update_dialog_vscroll(HWND hwnd, FX_PAGE_STATE *state,
	int min_content_height)
{
	RECT client;
	SCROLLINFO info;
	BOOL changed;
	BOOL need_scroll;
	int page_height;
	int pass;

	if (min_content_height < 1)
		min_content_height = 1;

	for (pass = 0; pass < 3; pass++)
	{
		GetClientRect(hwnd, &client);
		page_height = client.bottom - client.top;
		need_scroll = page_height < min_content_height;

		changed = fx_set_dialog_vscroll_visible(hwnd, state, need_scroll);
		if (!changed)
			break;
	}

	GetClientRect(hwnd, &client);
	page_height = client.bottom - client.top;
	if (page_height < 1)
		page_height = 1;

	state->content_height = MAX(page_height, min_content_height);
	state->scroll_y = fx_clamp_scroll_pos(state->scroll_y,
		state->content_height, page_height);

	ZeroMemory(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
	info.nMin = 0;
	info.nMax = state->content_height - 1;
	info.nPage = (UINT)page_height;
	info.nPos = state->scroll_y;
	SetScrollInfo(hwnd, SB_VERT, &info, TRUE);
}

static void fx_layout_dialog(HWND hwnd, FX_PAGE_STATE *state)
{
	RECT client;
	RECT extension_bounds;
	int client_width;
	int client_height;
	int min_content_height;
	int scroll_y;
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
	int checkbox_height;
	int md5_width;
	int sha1_width;
	int crc32_width;
	int crc64_width;
	int sha256_width;
	int sha512_width;
	int hash_column_1;
	int hash_column_2_width;
	int hash_column_2;
	int hash_column_3_width;
	int hash_column_3;
	int button_width;
	int button_height;

	if (state && state->layout_in_progress)
		return;
	if (state)
		state->layout_in_progress = TRUE;

	min_content_height = fx_dialog_min_content_height(hwnd, state);
	if (state)
	{
		fx_update_dialog_vscroll(hwnd, state, min_content_height);
		GetClientRect(hwnd, &client);
		client_width = client.right - client.left;
		client_height = state->content_height;
		scroll_y = state->scroll_y;
	}
	else
	{
		GetClientRect(hwnd, &client);
		client_width = client.right - client.left;
		client_height = MAX(client.bottom - client.top, min_content_height);
		scroll_y = 0;
	}
	if (client_width < fx_dlg_x(hwnd, 1))
		client_width = fx_dlg_x(hwnd, 1);

	outer_x = fx_dlg_x(hwnd, 7);
	outer_y = fx_dlg_y(hwnd, 7);
	field_x = fx_dlg_x(hwnd, 17);
	group_width = MAX(client_width - outer_x * 2, fx_dlg_x(hwnd, 1));
	content_width = MAX(client_width - field_x * 2, fx_dlg_x(hwnd, 1));

	file_y = fx_dlg_y(hwnd, 7);
	file_height = fx_dlg_y(hwnd, 43);
	hash_y = fx_dlg_y(hwnd, 55);
	hash_height = fx_dlg_y(hwnd, 135);
	extension_y = fx_dlg_y(hwnd, FX_EXTENSION_Y_DLU);
	extension_height = MAX(fx_dlg_y(hwnd, 18), client_height - extension_y - outer_y);

	checkbox_height = fx_dlg_y(hwnd, 10);
	md5_width = fx_dlg_x(hwnd, 42);
	sha1_width = fx_dlg_x(hwnd, 45);
	crc32_width = fx_dlg_x(hwnd, 52);
	crc64_width = fx_dlg_x(hwnd, 52);
	sha256_width = fx_dlg_x(hwnd, 62);
	sha512_width = fx_dlg_x(hwnd, 62);
	hash_column_1 = field_x;
	hash_column_2_width = MAX(sha1_width, sha256_width);
	hash_column_2 = field_x + (content_width - hash_column_2_width) / 2;
	hash_column_3_width = MAX(crc32_width, sha512_width);
	hash_column_3 = client_width - field_x - hash_column_3_width;
	button_width = fx_dlg_x(hwnd, 60);
	button_height = fx_dlg_y(hwnd, 14);

	fx_move_dlg_item(hwnd, IDC_FILE_GROUP, outer_x, file_y - scroll_y,
		group_width, file_height);
	fx_move_dlg_item(hwnd, IDC_FILE_TYPE, field_x,
		fx_dlg_y(hwnd, 20) - scroll_y, content_width, fx_dlg_y(hwnd, 21));

	fx_move_dlg_item(hwnd, IDC_HASH_GROUP, outer_x, hash_y - scroll_y,
		group_width, hash_height);
	fx_move_dlg_item(hwnd, IDC_HASH_MD5, hash_column_1,
		fx_dlg_y(hwnd, 72) - scroll_y, md5_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_SHA1, hash_column_2,
		fx_dlg_y(hwnd, 72) - scroll_y, sha1_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_CRC32, hash_column_3,
		fx_dlg_y(hwnd, 72) - scroll_y, crc32_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_CRC64, hash_column_1,
		fx_dlg_y(hwnd, 86) - scroll_y, crc64_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_SHA256, hash_column_2,
		fx_dlg_y(hwnd, 86) - scroll_y, sha256_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_SHA512, hash_column_3,
		fx_dlg_y(hwnd, 86) - scroll_y, sha512_width, checkbox_height);
	fx_move_dlg_item(hwnd, IDC_HASH_START, field_x,
		fx_dlg_y(hwnd, 102) - scroll_y, button_width, button_height);
	fx_move_dlg_item(hwnd, IDC_HASH_COPY,
		client_width - field_x - button_width,
		fx_dlg_y(hwnd, 102) - scroll_y, button_width, button_height);
	fx_move_dlg_item(hwnd, IDC_HASH_PROGRESS, field_x,
		fx_dlg_y(hwnd, 122) - scroll_y, content_width, fx_dlg_y(hwnd, 10));
	fx_move_dlg_item(hwnd, IDC_HASH_STATUS, field_x,
		fx_dlg_y(hwnd, 136) - scroll_y, content_width, fx_dlg_y(hwnd, 8));
	fx_move_dlg_item(hwnd, IDC_HASH_RESULT, field_x,
		fx_dlg_y(hwnd, 148) - scroll_y, content_width, fx_dlg_y(hwnd, 34));

	fx_move_dlg_item(hwnd, IDC_EXTENSION_GROUP, outer_x,
		extension_y - scroll_y, group_width, extension_height);
	if (state && state->extension_handler)
	{
		extension_bounds.left = field_x;
		extension_bounds.top = extension_y + fx_dlg_y(hwnd, 12) - scroll_y;
		extension_bounds.right = field_x + content_width;
		extension_bounds.bottom = extension_y + extension_height -
			fx_dlg_y(hwnd, 7) - scroll_y;
		state->extension_handler->layout(state->extension_context, &extension_bounds);
	}

	if (state)
		state->layout_in_progress = FALSE;
}

static void fx_scroll_dialog_to(HWND hwnd, FX_PAGE_STATE *state, int y)
{
	RECT client;
	int page_height;

	GetClientRect(hwnd, &client);
	page_height = client.bottom - client.top;
	if (page_height < 1)
		page_height = 1;

	y = fx_clamp_scroll_pos(y, state->content_height, page_height);
	if (y == state->scroll_y)
		return;

	state->scroll_y = y;
	SendMessageW(hwnd, WM_SETREDRAW, FALSE, 0);
	fx_layout_dialog(hwnd, state);
	SendMessageW(hwnd, WM_SETREDRAW, TRUE, 0);
	RedrawWindow(hwnd, NULL, NULL,
		RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

static void fx_scroll_dialog_bar(HWND hwnd, FX_PAGE_STATE *state, WPARAM wparam)
{
	SCROLLINFO info;
	int position;
	int line;

	ZeroMemory(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = SIF_ALL;
	if (!GetScrollInfo(hwnd, SB_VERT, &info))
		return;

	position = state->scroll_y;
	line = fx_dlg_y(hwnd, 10);
	if (line < 1)
		line = 1;

	switch (LOWORD(wparam))
	{
	case SB_LINEUP:
		position -= line;
		break;
	case SB_LINEDOWN:
		position += line;
		break;
	case SB_PAGEUP:
		position -= (int)info.nPage;
		break;
	case SB_PAGEDOWN:
		position += (int)info.nPage;
		break;
	case SB_THUMBTRACK:
	case SB_THUMBPOSITION:
		position = info.nTrackPos;
		break;
	case SB_TOP:
		position = 0;
		break;
	case SB_BOTTOM:
		position = state->content_height;
		break;
	default:
		break;
	}

	fx_scroll_dialog_to(hwnd, state, position);
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

	if (state->layout_ready)
		fx_layout_dialog(hwnd, state);
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
	case WM_SHOWWINDOW:
	{
		FX_PAGE_STATE *state = (FX_PAGE_STATE *)GetWindowLongPtrW(hwnd, DWLP_USER);

		if (wparam && state && !state->layout_ready)
		{
			state->layout_ready = TRUE;
			fx_layout_dialog(hwnd, state);
		}
		return TRUE;
	}
	case WM_SIZE:
	{
		FX_PAGE_STATE *state = (FX_PAGE_STATE *)GetWindowLongPtrW(hwnd, DWLP_USER);

		if (state && state->layout_ready && !state->layout_in_progress)
			fx_layout_dialog(hwnd, state);
		return TRUE;
	}
	case WM_VSCROLL:
	{
		FX_PAGE_STATE *state = (FX_PAGE_STATE *)GetWindowLongPtrW(hwnd, DWLP_USER);

		if (state && lparam == 0)
		{
			fx_scroll_dialog_bar(hwnd, state, wparam);
			return TRUE;
		}
		break;
	}
	case WM_MOUSEWHEEL:
	{
		FX_PAGE_STATE *state = (FX_PAGE_STATE *)GetWindowLongPtrW(hwnd, DWLP_USER);

		if (state && state->scroll_vert_visible)
		{
			int delta = (short)HIWORD(wparam);
			int line = fx_dlg_y(hwnd, 30);

			if (line < 1)
				line = 1;
			fx_scroll_dialog_to(hwnd, state,
				state->scroll_y - MulDiv(delta, line, WHEEL_DELTA));
			return TRUE;
		}
		break;
	}
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
			break;
		}
		break;
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
			if (state->hash_thread)
				CancelSynchronousIo(state->hash_thread);
			fx_close_hash_thread(state);
			fx_destroy_extension(state);
			state->hwnd = NULL;
			SetWindowLongPtrW(hwnd, DWLP_USER, 0);
		}
		return TRUE;
	}
	default:
		break;
	}

	{
		FX_PAGE_STATE *state = (FX_PAGE_STATE *)GetWindowLongPtrW(hwnd, DWLP_USER);
		LRESULT result;

		if (state && state->extension_handler && state->extension_handler->message &&
			state->extension_handler->message(state->extension_context, message, wparam,
				lparam, &result))
			return (INT_PTR)result;
	}

	return FALSE;
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
