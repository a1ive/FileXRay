/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "extensions.h"
#include "../pe.h"

#include <commctrl.h>
#include <shlwapi.h>
#include <stddef.h>
#include <string.h>
#include <strsafe.h>

#pragma comment(lib, "shlwapi.lib")

#define FX_EXE_ID_TREE          3201
#define FX_EXE_MAX_DLL_NODES    4096U
#define FX_EXE_MAX_NAME_CCH     512U

typedef enum FX_EXE_DEP_TYPE
{
	FX_DEP_NORMAL = 0,
	FX_DEP_DELAY_LOAD,
	FX_DEP_FORWARDED,
	FX_DEP_API_SET
} FX_EXE_DEP_TYPE;

typedef enum FX_EXE_DEP_STATUS
{
	FX_STATUS_OK = 0,
	FX_STATUS_NOT_FOUND,
	FX_STATUS_API_SET_RESOLVED,
	FX_STATUS_FORWARD_TARGET
} FX_EXE_DEP_STATUS;

typedef struct FX_EXE_DEP_NODE
{
	WCHAR name[FX_EXE_MAX_NAME_CCH];
	WCHAR resolved_host[FX_EXE_MAX_NAME_CCH];
	WCHAR resolved_path[MAX_PATH];
	FX_EXE_DEP_TYPE type;
	FX_EXE_DEP_STATUS status;
	DWORD function_count;
	BOOL is_api_set;
} FX_EXE_DEP_NODE;

typedef struct FX_EXE_VIEW
{
	HWND parent;
	HWND tree;
	WCHAR exe_dir[MAX_PATH];
	FX_EXE_DEP_NODE *nodes;
	DWORD node_count;
	DWORD node_capacity;
} FX_EXE_VIEW;

/* ---- API Set resolution ------------------------------------------------ */

/*
 * API_SET_NAMESPACE layout (v2-v6, Windows 10+).
 * We read from the current process PEB which is always available.
 */
typedef struct FX_API_SET_NAMESPACE_V6
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} FX_API_SET_NAMESPACE_V6;

typedef struct FX_API_SET_NAMESPACE_ENTRY_V6
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG HashedLength;
	ULONG ValueOffset;
	ULONG ValueCount;
} FX_API_SET_NAMESPACE_ENTRY_V6;

typedef struct FX_API_SET_VALUE_ENTRY_V6
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} FX_API_SET_VALUE_ENTRY_V6;

typedef struct FX_API_SET_HASH_ENTRY_V6
{
	ULONG Hash;
	ULONG Index;
} FX_API_SET_HASH_ENTRY_V6;

/*
 * Check if a DLL name looks like an API Set reference.
 * API Set names start with "api-" or "ext-" (case-insensitive).
 */
static BOOL fx_exe_is_api_set_name(PCWSTR name)
{
	if (_wcsnicmp(name, L"api-", 4) == 0)
		return TRUE;
	if (_wcsnicmp(name, L"ext-", 4) == 0)
		return TRUE;
	return FALSE;
}

/*
 * Resolve an API Set name to the host DLL using the process PEB's
 * ApiSetMap.  Returns TRUE if resolved, FALSE otherwise.
 */
static BOOL fx_exe_resolve_api_set(PCWSTR api_set_name, WCHAR *host,
	size_t host_cch)
{
	const FX_API_SET_NAMESPACE_V6 *ns;
	const FX_API_SET_NAMESPACE_ENTRY_V6 *entries;
	const FX_API_SET_HASH_ENTRY_V6 *hashes;
	WCHAR lower[FX_EXE_MAX_NAME_CCH];
	size_t name_len;
	size_t hash_len;
	ULONG hash;
	ULONG index;
	ULONG i;

	host[0] = L'\0';

	/*
	 * Read the PEB to get the ApiSetMap pointer.
	 * The PEB is at a fixed offset from TEB on both x86 and x64.
	 */
#if defined(_M_X64) || defined(_M_AMD64)
	{
		const BYTE *peb = (const BYTE *)__readgsqword(0x60);
		ns = *(const FX_API_SET_NAMESPACE_V6 **)(peb + 0x68);
	}
#elif defined(_M_IX86)
	{
		const BYTE *peb = (const BYTE *)__readfsdword(0x30);
		ns = *(const FX_API_SET_NAMESPACE_V6 **)(peb + 0x38);
	}
#elif defined(_M_ARM64)
	{
		/* ARM64 PEB via NtCurrentTeb()->ProcessEnvironmentBlock */
		const BYTE *teb = (const BYTE *)__getReg(18);
		const BYTE *peb = *(const BYTE **)(teb + 0x60);
		ns = *(const FX_API_SET_NAMESPACE_V6 **)(peb + 0x68);
	}
#else
	return FALSE;
#endif

	if (!ns || ns->Version < 2 || ns->Version > 6)
		return FALSE;

	/* Only handle v6 (Windows 10+) for now. */
	if (ns->Version != 6)
		return FALSE;

	/* Build lowercase copy and strip trailing ".dll" if present. */
	if (FAILED(StringCchCopyW(lower, ARRAYSIZE(lower), api_set_name)))
		return FALSE;
	_wcslwr_s(lower, ARRAYSIZE(lower));

	name_len = wcslen(lower);
	if (name_len >= 4 && wcscmp(lower + name_len - 4, L".dll") == 0)
	{
		lower[name_len - 4] = L'\0';
		name_len -= 4;
	}

	/* Hash the name up to the last hyphen (the "hashed length"). */
	hash_len = name_len;
	{
		const WCHAR *last_hyphen = wcsrchr(lower, L'-');
		if (last_hyphen)
			hash_len = (size_t)(last_hyphen - lower);
	}

	hash = 0;
	for (i = 0; i < (ULONG)hash_len; i++)
		hash = hash * ns->HashFactor + (ULONG)lower[i];

	/* Binary search in the hash table. */
	hashes = (const FX_API_SET_HASH_ENTRY_V6 *)((const BYTE *)ns +
		ns->HashOffset);
	entries = (const FX_API_SET_NAMESPACE_ENTRY_V6 *)((const BYTE *)ns +
		ns->EntryOffset);

	index = (ULONG)-1;
	{
		ULONG lo = 0, hi = ns->Count;

		while (lo < hi)
		{
			ULONG mid = lo + (hi - lo) / 2;

			if (hashes[mid].Hash == hash)
			{
				index = hashes[mid].Index;
				break;
			}
			else if (hashes[mid].Hash < hash)
			{
				lo = mid + 1;
			}
			else
			{
				hi = mid;
			}
		}
	}

	if (index == (ULONG)-1 || index >= ns->Count)
		return FALSE;

	{
		const FX_API_SET_NAMESPACE_ENTRY_V6 *entry = &entries[index];
		const WCHAR *entry_name = (const WCHAR *)((const BYTE *)ns +
			entry->NameOffset);
		size_t entry_name_len = entry->HashedLength / sizeof(WCHAR);
		const FX_API_SET_VALUE_ENTRY_V6 *values;

		/* Verify the name prefix matches. */
		if (entry_name_len > name_len)
			return FALSE;
		if (_wcsnicmp(lower, entry_name, entry_name_len) != 0)
			return FALSE;

		if (entry->ValueCount == 0)
			return FALSE;

		values = (const FX_API_SET_VALUE_ENTRY_V6 *)((const BYTE *)ns +
			entry->ValueOffset);

		/*
		 * Use the default (last) value entry.  In the v6 schema,
		 * if there are multiple values, the last one is the default
		 * host and the others are per-importing-module overrides.
		 */
		{
			const FX_API_SET_VALUE_ENTRY_V6 *val;
			const WCHAR *host_str;
			size_t host_len;

			if (entry->ValueCount > 1)
				val = &values[entry->ValueCount - 1];
			else
				val = &values[0];

			host_str = (const WCHAR *)((const BYTE *)ns +
				val->ValueOffset);
			host_len = val->ValueLength / sizeof(WCHAR);

			if (host_len == 0)
				return FALSE;
			if (host_len >= host_cch)
				host_len = host_cch - 1;

			memcpy(host, host_str, host_len * sizeof(WCHAR));
			host[host_len] = L'\0';
		}
	}

	return TRUE;
}

static BOOL fx_exe_try_path(WCHAR *result, size_t cch, PCWSTR dir,
	PCWSTR name)
{
	if (FAILED(StringCchCopyW(result, cch, dir)))
		return FALSE;
	if (FAILED(StringCchCatW(result, cch, L"\\")))
		return FALSE;
	if (FAILED(StringCchCatW(result, cch, name)))
		return FALSE;
	return (GetFileAttributesW(result) != INVALID_FILE_ATTRIBUTES);
}

static BOOL fx_exe_resolve_path(PCWSTR exe_dir, PCWSTR dll_name,
	WCHAR *result, size_t cch)
{
	WCHAR *dir_buf = NULL;
	WCHAR *path_env = NULL;
	DWORD path_cch;
	BOOL found = FALSE;

	result[0] = L'\0';

	/* 1. Same directory as the EXE. */
	if (fx_exe_try_path(result, cch, exe_dir, dll_name))
		return TRUE;

	dir_buf = (WCHAR *)HeapAlloc(GetProcessHeap(), 0,
		MAX_PATH * sizeof(WCHAR));
	if (!dir_buf)
		return FALSE;

	/* 2. System32 (or SysWOW64 for 32-bit on WoW64). */
	if (GetSystemDirectoryW(dir_buf, MAX_PATH) > 0)
	{
		if (fx_exe_try_path(result, cch, dir_buf, dll_name))
		{
			found = TRUE;
			goto done;
		}
	}

	/* 3. Windows directory. */
	if (GetWindowsDirectoryW(dir_buf, MAX_PATH) > 0)
	{
		if (fx_exe_try_path(result, cch, dir_buf, dll_name))
		{
			found = TRUE;
			goto done;
		}
	}

	/* 4. PATH directories. */
	path_cch = GetEnvironmentVariableW(L"PATH", NULL, 0);
	if (path_cch > 0)
	{
		path_env = (WCHAR *)HeapAlloc(GetProcessHeap(), 0,
			(size_t)path_cch * sizeof(WCHAR));
		if (path_env &&
			GetEnvironmentVariableW(L"PATH", path_env, path_cch) > 0)
		{
			WCHAR *token;
			WCHAR *next_token = NULL;

			token = wcstok_s(path_env, L";", &next_token);
			while (token)
			{
				if (fx_exe_try_path(result, cch, token, dll_name))
				{
					found = TRUE;
					goto done;
				}
				token = wcstok_s(NULL, L";", &next_token);
			}
		}
	}

done:
	if (path_env)
		HeapFree(GetProcessHeap(), 0, path_env);
	if (dir_buf)
		HeapFree(GetProcessHeap(), 0, dir_buf);
	return found;
}

/*
 * Check whether any export of a DLL is a forwarder and collect the
 * forwarded target DLL names.  We only check a few exports to avoid
 * being too slow.
 */
typedef struct FX_EXE_FORWARD_CTX
{
	FX_EXE_VIEW *view;
	PCWSTR parent_name;
} FX_EXE_FORWARD_CTX;

static void fx_exe_check_forwarded_exports(FX_EXE_VIEW *view,
	PCWSTR dll_path, PCWSTR parent_name)
{
	FX_PE_IMAGE image;
	IMAGE_DATA_DIRECTORY export_dir;
	const IMAGE_EXPORT_DIRECTORY *directory;
	const DWORD *function_rvas;
	DWORD export_rva_start;
	DWORD export_rva_end;
	DWORD index;
	HRESULT hr;

	if (FAILED(fx_pe_open(dll_path, &image)))
		return;

	hr = fx_pe_get_data_directory(&image, IMAGE_DIRECTORY_ENTRY_EXPORT,
		&export_dir);
	if (FAILED(hr) || hr == S_FALSE || export_dir.VirtualAddress == 0)
		goto done;

	export_rva_start = export_dir.VirtualAddress;
	export_rva_end = export_dir.VirtualAddress + export_dir.Size;

	hr = fx_pe_rva_to_pointer(&image, export_dir.VirtualAddress,
		sizeof(*directory), (const void **)&directory, NULL);
	if (FAILED(hr) || directory->NumberOfFunctions == 0)
		goto done;

	if (directory->NumberOfFunctions > 65536U)
		goto done;

	hr = fx_pe_rva_to_pointer(&image, directory->AddressOfFunctions,
		(size_t)directory->NumberOfFunctions * sizeof(DWORD),
		(const void **)&function_rvas, NULL);
	if (FAILED(hr))
		goto done;

	for (index = 0; index < directory->NumberOfFunctions; index++)
	{
		DWORD rva = function_rvas[index];
		const char *forward_str;
		const char *dot;
		WCHAR forward_dll[FX_EXE_MAX_NAME_CCH];
		DWORD ni;
		BOOL already_present;
		size_t dll_name_len;

		if (rva == 0)
			continue;
		if (rva < export_rva_start || rva >= export_rva_end)
			continue;

		/* This export is a forwarder. */
		hr = fx_pe_rva_to_pointer(&image, rva, 1,
			(const void **)&forward_str, NULL);
		if (FAILED(hr))
			continue;

		/* Extract the target DLL name (before the '.') */
		dot = strchr(forward_str, '.');
		if (!dot || dot == forward_str)
			continue;

		dll_name_len = (size_t)(dot - forward_str);
		if (dll_name_len >= FX_EXE_MAX_NAME_CCH - 5)
			continue;

		{
			size_t ci;

			for (ci = 0; ci < dll_name_len; ci++)
				forward_dll[ci] = (WCHAR)(BYTE)forward_str[ci];
			forward_dll[dll_name_len] = L'\0';
			StringCchCatW(forward_dll, ARRAYSIZE(forward_dll), L".dll");
		}

		/* Check if already in our node list. */
		already_present = FALSE;
		for (ni = 0; ni < view->node_count; ni++)
		{
			if (_wcsicmp(view->nodes[ni].name, forward_dll) == 0)
			{
				already_present = TRUE;
				break;
			}
		}

		if (!already_present &&
			view->node_count < view->node_capacity)
		{
			FX_EXE_DEP_NODE *node = &view->nodes[view->node_count];

			StringCchCopyW(node->name, ARRAYSIZE(node->name),
				forward_dll);
			node->type = FX_DEP_FORWARDED;
			node->status = FX_STATUS_FORWARD_TARGET;
			node->function_count = 0;
			node->is_api_set = FALSE;

			if (fx_exe_resolve_path(view->exe_dir, forward_dll,
				node->resolved_path,
				ARRAYSIZE(node->resolved_path)))
			{
				node->status = FX_STATUS_OK;
			}
			else
			{
				node->status = FX_STATUS_NOT_FOUND;
			}

			view->node_count++;
		}
	}

done:
	fx_pe_close(&image);
}

static void fx_exe_check_sxs_manifest(FX_EXE_VIEW *view, PCWSTR exe_path)
{
	WCHAR manifest_path[MAX_PATH];
	HANDLE file;
	BYTE buffer[4096];
	DWORD bytes_read;
	char *text;
	char *pos;

	/* Look for <exe_name>.exe.manifest alongside the EXE. */
	if (FAILED(StringCchCopyW(manifest_path, ARRAYSIZE(manifest_path),
		exe_path)))
		return;
	if (FAILED(StringCchCatW(manifest_path, ARRAYSIZE(manifest_path),
		L".manifest")))
		return;

	file = CreateFileW(manifest_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;

	if (!ReadFile(file, buffer, sizeof(buffer) - 1, &bytes_read, NULL) ||
		bytes_read == 0)
	{
		CloseHandle(file);
		return;
	}
	CloseHandle(file);
	buffer[bytes_read] = '\0';
	text = (char *)buffer;

	/*
	 * Very minimal XML parsing: scan for assemblyIdentity name="..."
	 * attributes within <dependency> elements.  This is intentionally
	 * simple and only handles the most common SxS manifest patterns.
	 */
	pos = text;
	while ((pos = strstr(pos, "assemblyIdentity")) != NULL)
	{
		char *name_attr;
		char *quote_start;
		char *quote_end;
		WCHAR assembly_name[FX_EXE_MAX_NAME_CCH];
		WCHAR sxs_dll[FX_EXE_MAX_NAME_CCH];
		size_t len;
		size_t ci;
		BOOL already;
		DWORD ni;

		pos += 16; /* skip "assemblyIdentity" */

		name_attr = strstr(pos, "name=\"");
		if (!name_attr || name_attr > pos + 512)
			continue;

		quote_start = name_attr + 6;
		quote_end = strchr(quote_start, '"');
		if (!quote_end)
			break;

		len = (size_t)(quote_end - quote_start);
		if (len == 0 || len >= ARRAYSIZE(assembly_name))
			continue;

		for (ci = 0; ci < len; ci++)
			assembly_name[ci] = (WCHAR)(BYTE)quote_start[ci];
		assembly_name[len] = L'\0';

		/* Try to find a DLL with this assembly name in a subdirectory. */
		StringCchCopyW(sxs_dll, ARRAYSIZE(sxs_dll), assembly_name);
		StringCchCatW(sxs_dll, ARRAYSIZE(sxs_dll), L".dll");

		already = FALSE;
		for (ni = 0; ni < view->node_count; ni++)
		{
			if (_wcsicmp(view->nodes[ni].name, sxs_dll) == 0)
			{
				already = TRUE;
				break;
			}
		}

		if (!already && view->node_count < view->node_capacity)
		{
			FX_EXE_DEP_NODE *node = &view->nodes[view->node_count];
			WCHAR sxs_path[MAX_PATH];
			BOOL found = FALSE;

			StringCchCopyW(node->name, ARRAYSIZE(node->name), sxs_dll);
			node->type = FX_DEP_NORMAL;
			node->status = FX_STATUS_NOT_FOUND;
			node->function_count = 0;
			node->is_api_set = FALSE;
			node->resolved_path[0] = L'\0';

			/* Check <exe_dir>\<assembly_name>\<dll_name> */
			if (SUCCEEDED(StringCchPrintfW(sxs_path,
				ARRAYSIZE(sxs_path), L"%s\\%s\\%s",
				view->exe_dir, assembly_name, sxs_dll)))
			{
				if (GetFileAttributesW(sxs_path) !=
					INVALID_FILE_ATTRIBUTES)
				{
					StringCchCopyW(node->resolved_path,
						ARRAYSIZE(node->resolved_path), sxs_path);
					node->status = FX_STATUS_OK;
					found = TRUE;
				}
			}

			if (!found)
			{
				if (fx_exe_resolve_path(view->exe_dir, sxs_dll,
					node->resolved_path,
					ARRAYSIZE(node->resolved_path)))
				{
					node->status = FX_STATUS_OK;
				}
			}

			view->node_count++;
		}

		pos = quote_end + 1;
	}
}

typedef struct FX_EXE_IMPORT_CTX
{
	FX_EXE_VIEW *view;
} FX_EXE_IMPORT_CTX;

/*
 * Find or create a dependency node for the given DLL name.
 * Returns the node index, or (DWORD)-1 on failure.
 */
static DWORD fx_exe_find_or_add_node(FX_EXE_VIEW *view,
	const WCHAR *dll_name, BOOL is_delay_load)
{
	DWORD index;

	for (index = 0; index < view->node_count; index++)
	{
		if (_wcsicmp(view->nodes[index].name, dll_name) == 0)
			return index;
	}

	if (view->node_count >= view->node_capacity)
		return (DWORD)-1;

	{
		FX_EXE_DEP_NODE *node = &view->nodes[view->node_count];

		ZeroMemory(node, sizeof(*node));
		StringCchCopyW(node->name, ARRAYSIZE(node->name), dll_name);
		node->type = is_delay_load ? FX_DEP_DELAY_LOAD : FX_DEP_NORMAL;
		node->status = FX_STATUS_OK;
		node->is_api_set = fx_exe_is_api_set_name(dll_name);

		/* Resolve API Set to host DLL. */
		if (node->is_api_set)
		{
			if (fx_exe_resolve_api_set(dll_name, node->resolved_host,
				ARRAYSIZE(node->resolved_host)))
			{
				node->status = FX_STATUS_API_SET_RESOLVED;

				if (!fx_exe_resolve_path(view->exe_dir,
					node->resolved_host, node->resolved_path,
					ARRAYSIZE(node->resolved_path)))
				{
					node->status = FX_STATUS_NOT_FOUND;
				}
			}
			else
			{
				node->status = FX_STATUS_NOT_FOUND;
			}
		}
		else
		{
			if (!fx_exe_resolve_path(view->exe_dir, dll_name,
				node->resolved_path, ARRAYSIZE(node->resolved_path)))
			{
				node->status = FX_STATUS_NOT_FOUND;
			}
		}
	}

	return view->node_count++;
}

static HRESULT fx_exe_import_callback(void *context, const char *dll_name,
	const char *function_name, WORD ordinal, WORD hint,
	BOOL is_delay_load)
{
	FX_EXE_IMPORT_CTX *ctx = (FX_EXE_IMPORT_CTX *)context;
	WCHAR wide_name[FX_EXE_MAX_NAME_CCH];
	size_t len;
	size_t ci;
	DWORD index;

	UNREFERENCED_PARAMETER(function_name);
	UNREFERENCED_PARAMETER(ordinal);
	UNREFERENCED_PARAMETER(hint);

	/* Convert ASCII dll_name to wide. */
	len = strlen(dll_name);
	if (len >= ARRAYSIZE(wide_name))
		len = ARRAYSIZE(wide_name) - 1;
	for (ci = 0; ci < len; ci++)
		wide_name[ci] = (WCHAR)(BYTE)dll_name[ci];
	wide_name[len] = L'\0';

	index = fx_exe_find_or_add_node(ctx->view, wide_name, is_delay_load);
	if (index != (DWORD)-1)
		ctx->view->nodes[index].function_count++;

	return S_OK;
}

static void fx_exe_populate_tree(FX_EXE_VIEW *view)
{
	DWORD index;

	SendMessageW(view->tree, WM_SETREDRAW, FALSE, 0);
	SendMessageW(view->tree, TVM_DELETEITEM, 0,
		(LPARAM)TVI_ROOT);

	for (index = 0; index < view->node_count; index++)
	{
		FX_EXE_DEP_NODE *node = &view->nodes[index];
		TVINSERTSTRUCTW tvis;
		WCHAR display[1024];
		HTREEITEM parent_item;
		WCHAR func_count_text[64];

		/* Build display text. */
		display[0] = L'\0';
		StringCchCopyW(display, ARRAYSIZE(display), node->name);

		/* Append type annotation. */
		switch (node->type)
		{
		case FX_DEP_DELAY_LOAD:
			StringCchCatW(display, ARRAYSIZE(display),
				L"  [Delay Load]");
			break;
		case FX_DEP_FORWARDED:
			StringCchCatW(display, ARRAYSIZE(display),
				L"  [Forwarded]");
			break;
		default:
			break;
		}

		/* Append API Set resolution. */
		if (node->is_api_set &&
			node->status == FX_STATUS_API_SET_RESOLVED &&
			node->resolved_host[0] != L'\0')
		{
			StringCchCatW(display, ARRAYSIZE(display), L"  \x2192 ");
			StringCchCatW(display, ARRAYSIZE(display),
				node->resolved_host);
		}



		/* Insert DLL node. */
		ZeroMemory(&tvis, sizeof(tvis));
		tvis.hParent = TVI_ROOT;
		tvis.hInsertAfter = TVI_LAST;
		tvis.item.mask = TVIF_TEXT;
		tvis.item.pszText = display;
		parent_item = (HTREEITEM)SendMessageW(view->tree,
			TVM_INSERTITEMW, 0, (LPARAM)&tvis);

		if (!parent_item)
			continue;

		/* Add child: function count. */
		if (node->function_count > 0)
		{
			StringCchPrintfW(func_count_text,
				ARRAYSIZE(func_count_text),
				L"Functions: %lu", (unsigned long)node->function_count);

			ZeroMemory(&tvis, sizeof(tvis));
			tvis.hParent = parent_item;
			tvis.hInsertAfter = TVI_LAST;
			tvis.item.mask = TVIF_TEXT;
			tvis.item.pszText = func_count_text;
			SendMessageW(view->tree, TVM_INSERTITEMW, 0,
				(LPARAM)&tvis);
		}

		/* Add child: resolved path. */
		if (node->resolved_path[0] != L'\0')
		{
			WCHAR path_text[MAX_PATH + 16];

			StringCchPrintfW(path_text, ARRAYSIZE(path_text),
				L"Path: %s", node->resolved_path);

			ZeroMemory(&tvis, sizeof(tvis));
			tvis.hParent = parent_item;
			tvis.hInsertAfter = TVI_LAST;
			tvis.item.mask = TVIF_TEXT;
			tvis.item.pszText = path_text;
			SendMessageW(view->tree, TVM_INSERTITEMW, 0,
				(LPARAM)&tvis);
		}
	}

	SendMessageW(view->tree, WM_SETREDRAW, TRUE, 0);
	InvalidateRect(view->tree, NULL, TRUE);
}

static HRESULT fx_exe_load(PCWSTR path, FX_EXE_VIEW *view)
{
	FX_PE_IMAGE image;
	FX_EXE_IMPORT_CTX ctx;
	DWORD index;
	HRESULT hr;

	/* Extract the directory containing the EXE. */
	StringCchCopyW(view->exe_dir, ARRAYSIZE(view->exe_dir), path);
	PathRemoveFileSpecW(view->exe_dir);

	/* Allocate node array. */
	view->node_capacity = FX_EXE_MAX_DLL_NODES;
	view->nodes = (FX_EXE_DEP_NODE *)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		(size_t)view->node_capacity * sizeof(FX_EXE_DEP_NODE));
	if (!view->nodes)
		return E_OUTOFMEMORY;

	hr = fx_pe_open(path, &image);
	if (FAILED(hr))
		return hr;

	/* Enumerate regular imports. */
	ctx.view = view;
	hr = fx_pe_enum_imports(&image, fx_exe_import_callback, &ctx);
	if (FAILED(hr))
	{
		fx_pe_close(&image);
		return hr;
	}

	/* Enumerate delay-load imports. */
	hr = fx_pe_enum_delay_imports(&image, fx_exe_import_callback, &ctx);
	fx_pe_close(&image);
	if (FAILED(hr))
		return hr;

	/* Check for forwarded exports in resolved DLLs. */
	{
		DWORD count_before = view->node_count;

		for (index = 0; index < count_before; index++)
		{
			if (view->nodes[index].resolved_path[0] != L'\0' &&
				view->nodes[index].status != FX_STATUS_NOT_FOUND)
			{
				fx_exe_check_forwarded_exports(view,
					view->nodes[index].resolved_path,
					view->nodes[index].name);
			}
		}
	}

	/* Check for SxS private manifest dependencies. */
	fx_exe_check_sxs_manifest(view, path);

	return S_OK;
}

static void fx_exe_destroy(void *context)
{
	FX_EXE_VIEW *view = (FX_EXE_VIEW *)context;

	if (view->tree)
		DestroyWindow(view->tree);
	if (view->nodes)
		HeapFree(GetProcessHeap(), 0, view->nodes);
	HeapFree(GetProcessHeap(), 0, view);
}

static HRESULT fx_exe_create(HWND parent, PCWSTR path, void **context)
{
	FX_EXE_VIEW *view;
	INITCOMMONCONTROLSEX common_controls;
	HINSTANCE instance;
	HFONT font;
	DWORD error;
	HRESULT hr;

	*context = NULL;
	view = (FX_EXE_VIEW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		sizeof(*view));
	if (!view)
		return E_OUTOFMEMORY;
	view->parent = parent;

	common_controls.dwSize = sizeof(common_controls);
	common_controls.dwICC = ICC_TREEVIEW_CLASSES;
	if (!InitCommonControlsEx(&common_controls))
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_GEN_FAILURE;
		hr = HRESULT_FROM_WIN32(error);
		goto fail;
	}

	instance = (HINSTANCE)(ULONG_PTR)GetWindowLongPtrW(parent,
		GWLP_HINSTANCE);
	view->tree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER |
			TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT |
			TVS_DISABLEDRAGDROP | TVS_SHOWSELALWAYS,
		0, 0, 0, 0, parent, (HMENU)(UINT_PTR)FX_EXE_ID_TREE,
		instance, NULL);
	if (!view->tree)
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_NOT_ENOUGH_MEMORY;
		hr = HRESULT_FROM_WIN32(error);
		goto fail;
	}

	font = (HFONT)SendMessageW(parent, WM_GETFONT, 0, 0);
	if (font)
		SendMessageW(view->tree, WM_SETFONT, (WPARAM)font, FALSE);

	hr = fx_exe_load(path, view);
	if (FAILED(hr))
		goto fail;

	fx_exe_populate_tree(view);

	*context = view;
	return S_OK;

fail:
	fx_exe_destroy(view);
	return hr;
}

static void fx_exe_layout(void *context, const RECT *bounds)
{
	FX_EXE_VIEW *view = (FX_EXE_VIEW *)context;
	int width;
	int height;

	width = bounds->right - bounds->left;
	height = bounds->bottom - bounds->top;
	MoveWindow(view->tree, bounds->left, bounds->top, width, height,
		TRUE);
}

const FX_EXTENSION_HANDLER fx_extension_exe_handler =
{
	L".exe",
	L"Dependencies",
	fx_exe_create,
	fx_exe_layout,
	fx_exe_destroy,
	NULL
};
