/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "pe.h"

#include <stddef.h>
#include <string.h>

HRESULT fx_pe_rva_to_pointer(const FX_PE_IMAGE *image, DWORD rva,
	size_t required, const void **pointer, size_t *available)
{
	size_t offset;
	size_t maximum;
	WORD index;

	*pointer = NULL;
	if (available)
		*available = 0;

	if (rva < image->size_of_headers)
	{
		offset = (size_t)rva;
		if (offset >= image->file_size)
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		maximum = image->file_size - offset;
		if ((size_t)(image->size_of_headers - rva) < maximum)
			maximum = image->size_of_headers - rva;
		if (required > maximum)
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		*pointer = image->base + offset;
		if (available)
			*available = maximum;
		return S_OK;
	}

	for (index = 0; index < image->section_count; index++)
	{
		const IMAGE_SECTION_HEADER *section = &image->sections[index];
		ULONGLONG section_start = section->VirtualAddress;
		ULONGLONG section_size = section->Misc.VirtualSize;
		ULONGLONG delta;
		ULONGLONG raw_offset;

		if (section->SizeOfRawData > section_size)
			section_size = section->SizeOfRawData;
		if ((ULONGLONG)rva < section_start ||
			(ULONGLONG)rva >= section_start + section_size)
			continue;

		delta = (ULONGLONG)rva - section_start;
		if (delta > section->SizeOfRawData ||
			(ULONGLONG)required > (ULONGLONG)section->SizeOfRawData - delta)
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		raw_offset = (ULONGLONG)section->PointerToRawData + delta;
		if (raw_offset > (ULONGLONG)(size_t)-1 ||
			raw_offset > image->file_size)
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		offset = (size_t)raw_offset;
		maximum = (size_t)((ULONGLONG)section->SizeOfRawData - delta);
		if (maximum > image->file_size - offset)
			maximum = image->file_size - offset;
		if (required > maximum)
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		*pointer = image->base + offset;
		if (available)
			*available = maximum;
		return S_OK;
	}

	return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
}

HRESULT fx_pe_parse(const void *base, size_t file_size, FX_PE_IMAGE *image)
{
	const IMAGE_DOS_HEADER *dos;
	const IMAGE_FILE_HEADER *fh;
	const BYTE *opt;
	size_t nt_offset;
	size_t optional_offset;
	size_t sections_offset;
	WORD magic;

	ZeroMemory(image, sizeof(*image));
	image->base = (const BYTE *)base;
	image->file_size = file_size;
	image->map_file = INVALID_HANDLE_VALUE;

	if (file_size < sizeof(IMAGE_DOS_HEADER))
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	dos = (const IMAGE_DOS_HEADER *)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	nt_offset = (size_t)dos->e_lfanew;
	if (nt_offset > file_size ||
		sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) >
			file_size - nt_offset)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	if (*(const DWORD *)(image->base + nt_offset) != IMAGE_NT_SIGNATURE)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	fh = (const IMAGE_FILE_HEADER *)(image->base + nt_offset +
		sizeof(DWORD));
	optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	if ((size_t)fh->SizeOfOptionalHeader > file_size - optional_offset)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	opt = image->base + optional_offset;
	magic = *(const WORD *)opt;
	if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		const IMAGE_OPTIONAL_HEADER32 *opt32 =
			(const IMAGE_OPTIONAL_HEADER32 *)opt;

		if ((size_t)fh->SizeOfOptionalHeader <
			offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders) +
				sizeof(opt32->SizeOfHeaders))
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		image->size_of_headers = opt32->SizeOfHeaders;
		image->is_64bit = FALSE;
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		const IMAGE_OPTIONAL_HEADER64 *opt64 =
			(const IMAGE_OPTIONAL_HEADER64 *)opt;

		if ((size_t)fh->SizeOfOptionalHeader <
			offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders) +
				sizeof(opt64->SizeOfHeaders))
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		image->size_of_headers = opt64->SizeOfHeaders;
		image->is_64bit = TRUE;
	}
	else
	{
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}

	sections_offset = optional_offset + fh->SizeOfOptionalHeader;
	if ((size_t)fh->NumberOfSections >
		(file_size - sections_offset) / sizeof(IMAGE_SECTION_HEADER))
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	image->file_header = fh;
	image->optional_header = opt;
	image->sections = (const IMAGE_SECTION_HEADER *)(image->base +
		sections_offset);
	image->section_count = fh->NumberOfSections;
	return S_OK;
}

HRESULT fx_pe_open(PCWSTR path, FX_PE_IMAGE *image)
{
	HANDLE file = INVALID_HANDLE_VALUE;
	HANDLE mapping = NULL;
	const void *view = NULL;
	LARGE_INTEGER file_size_value;
	size_t file_size;
	HRESULT hr;

	ZeroMemory(image, sizeof(*image));
	image->map_file = INVALID_HANDLE_VALUE;

	file = CreateFileW(path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	if (!GetFileSizeEx(file, &file_size_value) ||
		file_size_value.QuadPart <= 0)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto fail;
	}
	if ((ULONGLONG)file_size_value.QuadPart > (ULONGLONG)(size_t)-1)
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

	view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (!view)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	hr = fx_pe_parse(view, file_size, image);
	if (FAILED(hr))
		goto fail;

	image->map_file = file;
	image->map_mapping = mapping;
	return S_OK;

fail:
	if (view)
		UnmapViewOfFile(view);
	if (mapping)
		CloseHandle(mapping);
	if (file != INVALID_HANDLE_VALUE)
		CloseHandle(file);
	return hr;
}

void fx_pe_close(FX_PE_IMAGE *image)
{
	if (image->base)
		UnmapViewOfFile(image->base);
	if (image->map_mapping)
		CloseHandle(image->map_mapping);
	if (image->map_file != INVALID_HANDLE_VALUE)
		CloseHandle(image->map_file);
	ZeroMemory(image, sizeof(*image));
	image->map_file = INVALID_HANDLE_VALUE;
}

HRESULT fx_pe_get_data_directory(const FX_PE_IMAGE *image, DWORD index,
	IMAGE_DATA_DIRECTORY *directory)
{
	size_t directory_end;

	ZeroMemory(directory, sizeof(*directory));

	if (image->is_64bit)
	{
		const IMAGE_OPTIONAL_HEADER64 *opt64 =
			(const IMAGE_OPTIONAL_HEADER64 *)image->optional_header;

		if ((size_t)image->file_header->SizeOfOptionalHeader <
			offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes) +
				sizeof(opt64->NumberOfRvaAndSizes))
			return S_FALSE;
		if (opt64->NumberOfRvaAndSizes <= index)
			return S_FALSE;

		directory_end = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
			(index + 1U) * sizeof(IMAGE_DATA_DIRECTORY);
		if ((size_t)image->file_header->SizeOfOptionalHeader < directory_end)
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		*directory = opt64->DataDirectory[index];
	}
	else
	{
		const IMAGE_OPTIONAL_HEADER32 *opt32 =
			(const IMAGE_OPTIONAL_HEADER32 *)image->optional_header;

		if ((size_t)image->file_header->SizeOfOptionalHeader <
			offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes) +
				sizeof(opt32->NumberOfRvaAndSizes))
			return S_FALSE;
		if (opt32->NumberOfRvaAndSizes <= index)
			return S_FALSE;

		directory_end = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
			(index + 1U) * sizeof(IMAGE_DATA_DIRECTORY);
		if ((size_t)image->file_header->SizeOfOptionalHeader < directory_end)
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		*directory = opt32->DataDirectory[index];
	}

	return S_OK;
}

HRESULT fx_pe_get_image_base(const FX_PE_IMAGE *image,
	ULONGLONG *image_base)
{
	*image_base = 0;

	if (image->is_64bit)
	{
		const IMAGE_OPTIONAL_HEADER64 *opt64 =
			(const IMAGE_OPTIONAL_HEADER64 *)image->optional_header;

		if ((size_t)image->file_header->SizeOfOptionalHeader <
			offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase) +
				sizeof(opt64->ImageBase))
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		*image_base = opt64->ImageBase;
	}
	else
	{
		const IMAGE_OPTIONAL_HEADER32 *opt32 =
			(const IMAGE_OPTIONAL_HEADER32 *)image->optional_header;

		if ((size_t)image->file_header->SizeOfOptionalHeader <
			offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase) +
				sizeof(opt32->ImageBase))
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

		*image_base = opt32->ImageBase;
	}

	return S_OK;
}

HRESULT fx_pe_find_section(const FX_PE_IMAGE *image, const char *name,
	const IMAGE_SECTION_HEADER **section)
{
	WORD index;

	*section = NULL;
	for (index = 0; index < image->section_count; index++)
	{
		if (memcmp(image->sections[index].Name, name,
			IMAGE_SIZEOF_SHORT_NAME) == 0)
		{
			*section = &image->sections[index];
			break;
		}
	}

	return S_OK;
}
