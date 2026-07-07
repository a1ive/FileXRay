/* SPDX-License-Identifier: LGPL-3.0-or-later */
#ifndef FILEXRAY_PE_H
#define FILEXRAY_PE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FX_PE_IMAGE
{
	const BYTE *base;
	size_t file_size;
	const IMAGE_SECTION_HEADER *sections;
	WORD section_count;
	DWORD size_of_headers;
	const IMAGE_FILE_HEADER *file_header;
	const BYTE *optional_header;
	BOOL is_64bit;

	/* File mapping handles, managed by fx_pe_open / fx_pe_close. */
	HANDLE map_file;
	HANDLE map_mapping;
} FX_PE_IMAGE;

/*
 * fx_pe_parse validates a PE image that is already mapped into memory.
 * On success the caller-allocated FX_PE_IMAGE is populated. The caller
 * owns the memory buffer and must keep it alive while using the image.
 * map_file and map_mapping are left as NULL / INVALID_HANDLE_VALUE.
 */
HRESULT fx_pe_parse(const void *base, size_t file_size, FX_PE_IMAGE *image);

/*
 * fx_pe_open maps a file read-only and parses it as a PE image. The
 * caller must call fx_pe_close to unmap and close the handles.
 */
HRESULT fx_pe_open(PCWSTR path, FX_PE_IMAGE *image);

/*
 * fx_pe_close unmaps the view and closes the mapping handles that were
 * opened by fx_pe_open. Safe to call on an image populated by
 * fx_pe_parse (handles will be NULL and the call is a no-op).
 */
void fx_pe_close(FX_PE_IMAGE *image);

/*
 * fx_pe_rva_to_pointer translates an RVA to a pointer within the
 * mapped file buffer. required is the minimum number of bytes that
 * must be available at that address. available (optional) receives
 * the total bytes accessible from the returned pointer.
 */
HRESULT fx_pe_rva_to_pointer(const FX_PE_IMAGE *image, DWORD rva,
	size_t required, const void **pointer, size_t *available);

/*
 * fx_pe_get_data_directory retrieves a specific data-directory entry.
 * Returns S_FALSE if the entry index is beyond NumberOfRvaAndSizes
 * (directory will be zeroed in that case).
 */
HRESULT fx_pe_get_data_directory(const FX_PE_IMAGE *image, DWORD index,
	IMAGE_DATA_DIRECTORY *directory);

/*
 * fx_pe_get_image_base returns the ImageBase value for either PE32 or
 * PE32+ images.
 */
HRESULT fx_pe_get_image_base(const FX_PE_IMAGE *image,
	ULONGLONG *image_base);

/*
 * fx_pe_find_section locates a section header by its 8-byte name.
 * Sets *section to NULL if no matching section is found (returns S_OK).
 */
HRESULT fx_pe_find_section(const FX_PE_IMAGE *image, const char *name,
	const IMAGE_SECTION_HEADER **section);

/*
 * Callback invoked once per import entry (regular or delay-load).
 * Return S_OK to continue enumeration, or any failure HRESULT to stop.
 */
typedef HRESULT (*FX_PE_IMPORT_CALLBACK)(
	void *context,
	const char *dll_name,
	const char *function_name,
	WORD ordinal,
	WORD hint,
	BOOL is_delay_load
);

/*
 * Enumerate all regular imports from IMAGE_DIRECTORY_ENTRY_IMPORT.
 * The callback is invoked once per imported function, grouped by DLL.
 */
HRESULT fx_pe_enum_imports(const FX_PE_IMAGE *image,
	FX_PE_IMPORT_CALLBACK callback, void *context);

/*
 * Enumerate all delay-load imports from IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT.
 */
HRESULT fx_pe_enum_delay_imports(const FX_PE_IMAGE *image,
	FX_PE_IMPORT_CALLBACK callback, void *context);

#ifdef __cplusplus
}
#endif

#endif