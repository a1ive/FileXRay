/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "extensions.h"

#include <commctrl.h>
#include <stddef.h>
#include <string.h>
#include <strsafe.h>

#define FX_ISO_SECTOR_SIZE           2048U
#define FX_ISO_MAX_VD_SECTORS        256U
#define FX_ISO_MAX_SCAN_DIRS         512U
#define FX_ISO_MAX_BOOT_IMAGES       64U
#define FX_ISO_MAX_UDF_VDS_SECTORS   2048U

#define FX_ISO_ID_PANEL              3401
#define FX_ISO_ID_FEATURE_ISO9660    3402
#define FX_ISO_ID_FEATURE_JOLIET     3403
#define FX_ISO_ID_FEATURE_UDF        3404
#define FX_ISO_ID_FEATURE_RR         3405
#define FX_ISO_ID_FEATURE_ELTORITO   3406
#define FX_ISO_ID_FEATURE_HYBRID     3407
#define FX_ISO_ID_ISO_LABEL          3408
#define FX_ISO_ID_ISO_VALUE          3409
#define FX_ISO_ID_ISO_LOWERCASE      3410
#define FX_ISO_ID_ISO_DOS_CHARSET    3411
#define FX_ISO_ID_ISO_OMIT_VERSION   3412
#define FX_ISO_ID_JOLIET_LABEL       3413
#define FX_ISO_ID_JOLIET_VALUE       3414
#define FX_ISO_ID_RR_RATIONAL        3415
#define FX_ISO_ID_RR_RELOC           3416
#define FX_ISO_ID_UDF_LABEL          3417
#define FX_ISO_ID_UDF_VALUE          3418
#define FX_ISO_ID_BOOT_EFI           3419
#define FX_ISO_ID_BOOT_BIOS          3420
#define FX_ISO_ID_BOOT_MAC           3421
#define FX_ISO_ID_BOOT_LABEL         3422
#define FX_ISO_ID_BOOT_COMBO         3423
#define FX_ISO_ID_SECTION_FS         3424
#define FX_ISO_ID_SECTION_ISO9660    3425
#define FX_ISO_ID_SECTION_ROCK_RIDGE 3426
#define FX_ISO_ID_SECTION_JOLIET     3427
#define FX_ISO_ID_SECTION_UDF        3428
#define FX_ISO_ID_SECTION_EL_TORITO  3429

typedef enum FX_ISO_FILENAME_MODE
{
	FX_ISO_FILENAME_DOS = 0,
	FX_ISO_FILENAME_31,
	FX_ISO_FILENAME_221
} FX_ISO_FILENAME_MODE;

typedef struct FX_ISO_READER
{
	HANDLE file;
	ULONGLONG file_size;
	DWORD sector_count;
} FX_ISO_READER;

typedef struct FX_ISO_BOOT_IMAGE
{
	BYTE platform;
	BYTE media_type;
	BOOL bootable;
	WORD sectors;
	DWORD lba;
	WCHAR text[128];
} FX_ISO_BOOT_IMAGE;

typedef struct FX_ISO_INFO
{
	BOOL has_iso9660;
	BOOL has_joliet;
	BOOL has_udf;
	BOOL has_rock_ridge;
	BOOL has_el_torito;
	BOOL is_hybrid;
	BOOL iso_lowercase;
	BOOL iso_dos_charset;
	BOOL iso_omit_version;
	BOOL iso_needs_level2;
	BOOL iso_enhanced;
	DWORD iso_max_name_len;
	BOOL joliet_extended;
	BOOL rr_rational;
	BOOL rr_reloc;
	WCHAR udf_version[32];
	DWORD root_extent;
	DWORD root_size;
	DWORD boot_catalog_lba;
	BOOL boot_efi;
	BOOL boot_bios;
	BOOL boot_mac;
	FX_ISO_BOOT_IMAGE boot_images[FX_ISO_MAX_BOOT_IMAGES];
	UINT boot_image_count;
} FX_ISO_INFO;

typedef struct FX_ISO_DIR_ITEM
{
	DWORD extent;
	DWORD size;
	UINT depth;
} FX_ISO_DIR_ITEM;

typedef struct FX_ISO_VIEW
{
	HWND parent;
	HWND panel;
	WNDPROC old_panel_proc;
	int scroll_pos;
	int content_height;
	FX_ISO_INFO info;
	HWND fs_section_label;
	HWND feature_iso9660;
	HWND feature_joliet;
	HWND feature_udf;
	HWND feature_rock_ridge;
	HWND feature_el_torito;
	HWND feature_hybrid;
	HWND iso_section_label;
	HWND iso_label;
	HWND iso_value;
	HWND iso_lowercase;
	HWND iso_dos_charset;
	HWND iso_omit_version;
	HWND joliet_section_label;
	HWND joliet_label;
	HWND joliet_value;
	HWND rr_section_label;
	HWND rr_rational;
	HWND rr_reloc;
	HWND udf_section_label;
	HWND udf_label;
	HWND udf_value;
	HWND boot_section_label;
	HWND boot_efi;
	HWND boot_bios;
	HWND boot_mac;
	HWND boot_label;
	HWND boot_combo;
} FX_ISO_VIEW;

static WORD fx_iso_read_le16(const BYTE *data)
{
	return (WORD)((WORD)data[0] | ((WORD)data[1] << 8));
}

static DWORD fx_iso_read_le32(const BYTE *data)
{
	return (DWORD)data[0] | ((DWORD)data[1] << 8) |
		((DWORD)data[2] << 16) | ((DWORD)data[3] << 24);
}

static DWORD fx_iso_min_dword(DWORD left, DWORD right)
{
	return left < right ? left : right;
}

static HRESULT fx_iso_reader_open(PCWSTR path, FX_ISO_READER *reader)
{
	LARGE_INTEGER size;

	ZeroMemory(reader, sizeof(*reader));
	reader->file = CreateFileW(path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (reader->file == INVALID_HANDLE_VALUE)
		return HRESULT_FROM_WIN32(GetLastError());

	if (!GetFileSizeEx(reader->file, &size))
	{
		HRESULT hr = HRESULT_FROM_WIN32(GetLastError());

		CloseHandle(reader->file);
		reader->file = INVALID_HANDLE_VALUE;
		return hr;
	}
	if (size.QuadPart <= 0)
	{
		CloseHandle(reader->file);
		reader->file = INVALID_HANDLE_VALUE;
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}

	reader->file_size = (ULONGLONG)size.QuadPart;
	if (reader->file_size / FX_ISO_SECTOR_SIZE > MAXDWORD)
		reader->sector_count = MAXDWORD;
	else
		reader->sector_count = (DWORD)(reader->file_size / FX_ISO_SECTOR_SIZE);

	return S_OK;
}

static void fx_iso_reader_close(FX_ISO_READER *reader)
{
	if (reader->file != INVALID_HANDLE_VALUE)
		CloseHandle(reader->file);
	reader->file = INVALID_HANDLE_VALUE;
}

static HRESULT fx_iso_read_at(FX_ISO_READER *reader, ULONGLONG offset,
	void *buffer, DWORD bytes)
{
	LARGE_INTEGER position;
	BYTE *target = (BYTE *)buffer;
	DWORD total = 0;

	if (offset > reader->file_size || bytes > reader->file_size - offset)
		return HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
	if (offset > (ULONGLONG)MAXLONGLONG)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);

	position.QuadPart = (LONGLONG)offset;
	if (!SetFilePointerEx(reader->file, position, NULL, FILE_BEGIN))
		return HRESULT_FROM_WIN32(GetLastError());

	while (total < bytes)
	{
		DWORD chunk;
		DWORD read_now;

		chunk = bytes - total;
		read_now = 0;
		if (!ReadFile(reader->file, target + total, chunk, &read_now, NULL))
			return HRESULT_FROM_WIN32(GetLastError());
		if (read_now == 0)
			return HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
		total += read_now;
	}

	return S_OK;
}

static HRESULT fx_iso_read_sector(FX_ISO_READER *reader, DWORD lba,
	BYTE *sector)
{
	return fx_iso_read_at(reader, (ULONGLONG)lba * FX_ISO_SECTOR_SIZE,
		sector, FX_ISO_SECTOR_SIZE);
}

static BOOL fx_iso_descriptor_id_is_cd001(const BYTE *sector)
{
	return memcmp(sector + 1, "CD001", 5) == 0;
}

static BOOL fx_iso_is_joliet_escape(const BYTE *escape, BOOL *extended)
{
	if (escape[0] != '%' || escape[1] != '/')
		return FALSE;
	if (escape[2] == '@' || escape[2] == 'C')
	{
		*extended = FALSE;
		return TRUE;
	}
	if (escape[2] == 'E')
	{
		*extended = TRUE;
		return TRUE;
	}

	return FALSE;
}

static BOOL fx_iso_is_special_identifier(const BYTE *identifier,
	BYTE length)
{
	return length == 1 && (identifier[0] == 0 || identifier[0] == 1);
}

static DWORD fx_iso_identifier_base_length(const BYTE *identifier,
	BYTE length)
{
	DWORD index;

	for (index = 0; index < (DWORD)length; index++)
	{
		if (identifier[index] == ';')
			return index;
	}

	return (DWORD)length;
}

static BOOL fx_iso_is_strict_name_char(BYTE value)
{
	return (value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9') || value == '_';
}

static BOOL fx_iso_is_dos_extra_char(BYTE value)
{
	static const char extra[] = "!#$%&'()-@^`{}~+";

	return value >= 0x80 || (value != 0 && strchr(extra, (int)value) != NULL);
}

static BOOL fx_iso_identifier_is_dos_83(const BYTE *identifier,
	BYTE length, BOOL is_directory)
{
	DWORD base_length;
	DWORD index;
	DWORD name_length = 0;
	DWORD extension_length = 0;
	BOOL saw_dot = FALSE;

	base_length = fx_iso_identifier_base_length(identifier, length);
	if (base_length == 0)
		return FALSE;

	if (is_directory)
	{
		if (base_length > 8)
			return FALSE;
		for (index = 0; index < base_length; index++)
		{
			if (!fx_iso_is_strict_name_char(identifier[index]))
				return FALSE;
		}
		return TRUE;
	}

	for (index = 0; index < base_length; index++)
	{
		BYTE value = identifier[index];

		if (value == '.')
		{
			if (saw_dot)
				return FALSE;
			saw_dot = TRUE;
			continue;
		}

		if (!fx_iso_is_strict_name_char(value))
			return FALSE;
		if (saw_dot)
			extension_length++;
		else
			name_length++;
	}

	return name_length > 0 && name_length <= 8 && extension_length <= 3;
}

static void fx_iso_analyze_identifier(FX_ISO_INFO *info,
	const BYTE *identifier, BYTE length, BOOL is_directory)
{
	DWORD base_length;
	DWORD index;
	BOOL has_version = FALSE;

	if (fx_iso_is_special_identifier(identifier, length))
		return;

	base_length = fx_iso_identifier_base_length(identifier, length);
	if (base_length > info->iso_max_name_len)
		info->iso_max_name_len = base_length;

	for (index = 0; index < (DWORD)length; index++)
	{
		BYTE value = identifier[index];

		if (value == ';')
			has_version = TRUE;
		if (value >= 'a' && value <= 'z')
			info->iso_lowercase = TRUE;
		if (value != '.' && value != ';' && !fx_iso_is_strict_name_char(value) &&
			!(value >= 'a' && value <= 'z') && fx_iso_is_dos_extra_char(value))
			info->iso_dos_charset = TRUE;
	}

	if (!is_directory && !has_version)
		info->iso_omit_version = TRUE;
	if (!fx_iso_identifier_is_dos_83(identifier, length, is_directory))
		info->iso_needs_level2 = TRUE;
}

static BOOL fx_iso_entry_contains_ascii(const BYTE *entry, size_t entry_size,
	const char *text)
{
	size_t text_size = strlen(text);
	size_t index;

	if (text_size == 0 || text_size > entry_size)
		return FALSE;

	for (index = 0; index <= entry_size - text_size; index++)
	{
		if (memcmp(entry + index, text, text_size) == 0)
			return TRUE;
	}

	return FALSE;
}

static void fx_iso_scan_system_use(FX_ISO_INFO *info, const BYTE *system_use,
	size_t system_use_size)
{
	size_t offset = 0;

	while (offset + 4U <= system_use_size)
	{
		const BYTE *entry = system_use + offset;
		BYTE length = entry[2];

		if (length < 4 || offset + length > system_use_size)
			break;

		if (entry[0] == 'S' && entry[1] == 'T')
			break;
		if (entry[0] == 'E' && entry[1] == 'R')
		{
			if (fx_iso_entry_contains_ascii(entry, length, "RRIP") ||
				fx_iso_entry_contains_ascii(entry, length, "IEEE_P1282"))
			{
				info->has_rock_ridge = TRUE;
				info->rr_rational = TRUE;
			}
		}
		else if ((entry[0] == 'R' && entry[1] == 'R') ||
			(entry[0] == 'P' && entry[1] == 'X') ||
			(entry[0] == 'P' && entry[1] == 'N') ||
			(entry[0] == 'S' && entry[1] == 'L') ||
			(entry[0] == 'N' && entry[1] == 'M') ||
			(entry[0] == 'T' && entry[1] == 'F'))
		{
			info->has_rock_ridge = TRUE;
		}
		else if ((entry[0] == 'C' && entry[1] == 'L') ||
			(entry[0] == 'P' && entry[1] == 'L') ||
			(entry[0] == 'R' && entry[1] == 'E'))
		{
			info->has_rock_ridge = TRUE;
			info->rr_reloc = TRUE;
		}

		offset += length;
	}
}

static BOOL fx_iso_dir_item_seen(const FX_ISO_DIR_ITEM *items, UINT count,
	DWORD extent, DWORD size)
{
	UINT index;

	for (index = 0; index < count; index++)
	{
		if (items[index].extent == extent && items[index].size == size)
			return TRUE;
	}

	return FALSE;
}

static void fx_iso_scan_record(FX_ISO_INFO *info, const BYTE *record,
	BYTE record_length)
{
	BYTE identifier_length;
	const BYTE *identifier;
	size_t system_use_offset;
	BOOL is_directory;

	if (record_length < 34)
		return;

	identifier_length = record[32];
	if ((DWORD)identifier_length > (DWORD)record_length - 33U)
		return;

	identifier = record + 33;
	is_directory = (record[25] & 0x02) != 0;
	fx_iso_analyze_identifier(info, identifier, identifier_length,
		is_directory);

	system_use_offset = 33U + identifier_length;
	if ((identifier_length & 1U) == 0)
		system_use_offset++;
	if (system_use_offset < record_length)
	{
		fx_iso_scan_system_use(info, record + system_use_offset,
			(size_t)record_length - system_use_offset);
	}
}

static HRESULT fx_iso_scan_directories(FX_ISO_READER *reader,
	FX_ISO_INFO *info)
{
	FX_ISO_DIR_ITEM items[FX_ISO_MAX_SCAN_DIRS];
	UINT item_count = 0;
	UINT item_index = 0;
	BYTE sector[FX_ISO_SECTOR_SIZE];

	if (info->root_extent == 0 || info->root_size == 0)
		return S_OK;

	items[item_count].extent = info->root_extent;
	items[item_count].size = info->root_size;
	items[item_count].depth = 0;
	item_count++;

	while (item_index < item_count)
	{
		FX_ISO_DIR_ITEM item = items[item_index++];
		DWORD offset;
		DWORD bytes_to_scan;

		bytes_to_scan = item.size;
		for (offset = 0; offset < bytes_to_scan; offset += FX_ISO_SECTOR_SIZE)
		{
			DWORD lba = item.extent + offset / FX_ISO_SECTOR_SIZE;
			DWORD sector_bytes = fx_iso_min_dword(FX_ISO_SECTOR_SIZE,
				bytes_to_scan - offset);
			DWORD pos = 0;
			HRESULT hr;

			hr = fx_iso_read_sector(reader, lba, sector);
			if (FAILED(hr))
				return hr;

			while (pos < sector_bytes)
			{
				const BYTE *record = sector + pos;
				BYTE record_length = record[0];
				BYTE identifier_length;
				const BYTE *identifier;
				DWORD extent;
				DWORD size;
				BOOL is_directory;

				if (record_length == 0)
					break;
				if ((DWORD)record_length > sector_bytes - pos)
					break;

				fx_iso_scan_record(info, record, record_length);

				if (record_length >= 34)
				{
					identifier_length = record[32];
					identifier = record + 33;
					is_directory = (record[25] & 0x02) != 0;
					if (is_directory &&
						!fx_iso_is_special_identifier(identifier, identifier_length) &&
						item.depth < 32)
					{
						extent = fx_iso_read_le32(record + 2);
						size = fx_iso_read_le32(record + 10);
						if (extent != 0 && size != 0 &&
							item_count < FX_ISO_MAX_SCAN_DIRS &&
							!fx_iso_dir_item_seen(items, item_count, extent, size))
						{
							items[item_count].extent = extent;
							items[item_count].size = size;
							items[item_count].depth = item.depth + 1U;
							item_count++;
						}
					}
				}

				pos += record_length;
			}
		}
	}

	return S_OK;
}

static void fx_iso_parse_primary_volume_descriptor(FX_ISO_INFO *info,
	const BYTE *sector)
{
	const BYTE *root = sector + 156;

	info->has_iso9660 = TRUE;
	if (root[0] >= 34)
	{
		info->root_extent = fx_iso_read_le32(root + 2);
		info->root_size = fx_iso_read_le32(root + 10);
		fx_iso_scan_record(info, root, root[0]);
	}
}

static void fx_iso_parse_boot_record(FX_ISO_INFO *info, const BYTE *sector)
{
	if (memcmp(sector + 7, "EL TORITO SPECIFICATION", 23) != 0)
		return;

	info->has_el_torito = TRUE;
	info->boot_catalog_lba = fx_iso_read_le32(sector + 71);
}

static HRESULT fx_iso_parse_volume_descriptors(FX_ISO_READER *reader,
	FX_ISO_INFO *info)
{
	BYTE sector[FX_ISO_SECTOR_SIZE];
	DWORD index;

	for (index = 0; index < FX_ISO_MAX_VD_SECTORS; index++)
	{
		DWORD lba = 16U + index;
		HRESULT hr;

		hr = fx_iso_read_sector(reader, lba, sector);
		if (FAILED(hr))
			break;

		if (!fx_iso_descriptor_id_is_cd001(sector))
		{
			if (index == 0)
				break;
			continue;
		}

		switch (sector[0])
		{
		case 0:
			fx_iso_parse_boot_record(info, sector);
			break;
		case 1:
			fx_iso_parse_primary_volume_descriptor(info, sector);
			break;
		case 2:
		{
			BOOL extended = FALSE;

			if (fx_iso_is_joliet_escape(sector + 88, &extended))
			{
				info->has_joliet = TRUE;
				info->joliet_extended = extended;
			}
			else if (sector[6] == 2)
			{
				info->has_iso9660 = TRUE;
				info->iso_enhanced = TRUE;
			}
			break;
		}
		case 255:
			return S_OK;
		default:
			break;
		}
	}

	return S_OK;
}

static BOOL fx_iso_mbr_has_partition(const BYTE *sector)
{
	UINT index;

	if (sector[510] != 0x55 || sector[511] != 0xAA)
		return FALSE;

	for (index = 0; index < 4; index++)
	{
		const BYTE *entry = sector + 446U + (size_t)index * 16U;
		DWORD start_lba = fx_iso_read_le32(entry + 8);
		DWORD sectors = fx_iso_read_le32(entry + 12);

		if (entry[4] != 0 || start_lba != 0 || sectors != 0)
			return TRUE;
	}

	return FALSE;
}

static void fx_iso_detect_hybrid(FX_ISO_READER *reader, FX_ISO_INFO *info)
{
	BYTE sector[FX_ISO_SECTOR_SIZE];

	if (FAILED(fx_iso_read_sector(reader, 0, sector)))
		return;

	if (fx_iso_mbr_has_partition(sector))
	{
		info->is_hybrid = TRUE;
		return;
	}

	if ((sector[0] == 'E' && sector[1] == 'R') ||
		(sector[512] == 'P' && sector[513] == 'M'))
	{
		info->is_hybrid = TRUE;
	}
}

static PCWSTR fx_iso_boot_platform_text(BYTE platform)
{
	switch (platform)
	{
	case 0x00:
		return L"BIOS";
	case 0x01:
		return L"PowerPC";
	case 0x02:
		return L"Mac";
	case 0xEF:
		return L"EFI";
	default:
		return L"Unknown";
	}
}

static PCWSTR fx_iso_boot_media_text(BYTE media_type)
{
	switch (media_type)
	{
	case 0:
		return L"No-Emul";
	case 1:
		return L"1.2M-Floppy";
	case 2:
		return L"1.44M-Floppy";
	case 3:
		return L"2.88M-Floppy";
	case 4:
		return L"HDD";
	default:
		return L"Unknown";
	}
}

static void fx_iso_record_boot_platform(FX_ISO_INFO *info, BYTE platform)
{
	if (platform == 0xEF)
		info->boot_efi = TRUE;
	else if (platform == 0x00)
		info->boot_bios = TRUE;
	else if (platform == 0x01 || platform == 0x02)
		info->boot_mac = TRUE;
}

static HRESULT fx_iso_add_boot_image(FX_ISO_INFO *info, BYTE platform,
	const BYTE *entry)
{
	FX_ISO_BOOT_IMAGE *image;
	HRESULT hr;

	if (info->boot_image_count >= FX_ISO_MAX_BOOT_IMAGES)
		return S_OK;

	image = &info->boot_images[info->boot_image_count];
	ZeroMemory(image, sizeof(*image));
	image->platform = platform;
	image->bootable = entry[0] == 0x88;
	image->media_type = entry[1];
	image->sectors = fx_iso_read_le16(entry + 6);
	image->lba = fx_iso_read_le32(entry + 8);

	if (image->lba == 0 && image->sectors == 0 && !image->bootable)
		return S_OK;

	hr = StringCchPrintfW(image->text, ARRAYSIZE(image->text),
		L"%s/%s/LBA %lu/Sectors %u",
		fx_iso_boot_platform_text(platform),
		fx_iso_boot_media_text(image->media_type),
		(unsigned long)image->lba, (unsigned int)image->sectors);
	if (FAILED(hr))
		return hr;

	fx_iso_record_boot_platform(info, platform);
	info->boot_image_count++;
	return S_OK;
}

static HRESULT fx_iso_parse_el_torito(FX_ISO_READER *reader,
	FX_ISO_INFO *info)
{
	BYTE catalog[FX_ISO_SECTOR_SIZE];
	BYTE platform;
	DWORD offset;
	HRESULT hr;

	if (!info->has_el_torito || info->boot_catalog_lba == 0)
		return S_OK;

	hr = fx_iso_read_sector(reader, info->boot_catalog_lba, catalog);
	if (FAILED(hr))
		return S_OK;

	platform = catalog[1];
	fx_iso_record_boot_platform(info, platform);
	hr = fx_iso_add_boot_image(info, platform, catalog + 32);
	if (FAILED(hr))
		return hr;

	offset = 64;
	while (offset + 32U <= FX_ISO_SECTOR_SIZE)
	{
		BYTE indicator = catalog[offset];

		if (indicator == 0)
			break;

		if (indicator == 0x90 || indicator == 0x91)
		{
			BYTE header_indicator = indicator;
			WORD entry_count = fx_iso_read_le16(catalog + offset + 2);
			WORD entry_index;

			platform = catalog[offset + 1];
			fx_iso_record_boot_platform(info, platform);
			offset += 32;

			for (entry_index = 0; entry_index < entry_count &&
				offset + 32U <= FX_ISO_SECTOR_SIZE; entry_index++)
			{
				indicator = catalog[offset];
				if (indicator == 0x88 || indicator == 0x00)
				{
					hr = fx_iso_add_boot_image(info, platform,
						catalog + offset);
					if (FAILED(hr))
						return hr;
				}
				offset += 32;
			}

			if (header_indicator == 0x91)
				break;
			continue;
		}

		if (indicator == 0x88 || indicator == 0x00)
		{
			hr = fx_iso_add_boot_image(info, platform, catalog + offset);
			if (FAILED(hr))
				return hr;
		}

		offset += 32;
	}

	return S_OK;
}

static BOOL fx_iso_udf_tag_is(const BYTE *sector, WORD tag)
{
	return fx_iso_read_le16(sector) == tag;
}

static BOOL fx_iso_udf_revision_from_entity(const BYTE *entity, WORD *revision)
{
	if (memcmp(entity + 1, "*OSTA UDF", 9) != 0)
		return FALSE;

	*revision = fx_iso_read_le16(entity + 24);
	return *revision != 0;
}

static UINT fx_iso_bcd_byte_to_uint(BYTE value)
{
	BYTE high = (BYTE)(value >> 4);
	BYTE low = (BYTE)(value & 0x0F);

	if (high <= 9 && low <= 9)
		return (UINT)high * 10U + (UINT)low;
	return (UINT)value;
}

static HRESULT fx_iso_format_udf_revision(WORD revision, WCHAR *text,
	size_t text_cch)
{
	UINT major = fx_iso_bcd_byte_to_uint((BYTE)(revision >> 8));
	UINT minor = fx_iso_bcd_byte_to_uint((BYTE)(revision & 0xFF));

	return StringCchPrintfW(text, text_cch, L"%u.%02u", major, minor);
}

static HRESULT fx_iso_try_udf_anchor(FX_ISO_READER *reader, DWORD lba,
	DWORD *main_lba, DWORD *main_length)
{
	BYTE sector[FX_ISO_SECTOR_SIZE];
	HRESULT hr;

	if (lba >= reader->sector_count)
		return S_FALSE;

	hr = fx_iso_read_sector(reader, lba, sector);
	if (FAILED(hr))
		return S_FALSE;
	if (!fx_iso_udf_tag_is(sector, 2))
		return S_FALSE;

	*main_length = fx_iso_read_le32(sector + 16);
	*main_lba = fx_iso_read_le32(sector + 20);
	if (*main_length == 0 || *main_lba == 0)
		return S_FALSE;

	return S_OK;
}

static HRESULT fx_iso_scan_udf_volume_sequence(FX_ISO_READER *reader,
	FX_ISO_INFO *info, DWORD main_lba, DWORD main_length)
{
	BYTE sector[FX_ISO_SECTOR_SIZE];
	DWORD sector_count;
	DWORD index;

	sector_count = (main_length + FX_ISO_SECTOR_SIZE - 1U) /
		FX_ISO_SECTOR_SIZE;
	if (sector_count > FX_ISO_MAX_UDF_VDS_SECTORS)
		sector_count = FX_ISO_MAX_UDF_VDS_SECTORS;

	for (index = 0; index < sector_count; index++)
	{
		WORD tag;
		HRESULT hr;

		hr = fx_iso_read_sector(reader, main_lba + index, sector);
		if (FAILED(hr))
			return S_OK;

		tag = fx_iso_read_le16(sector);
		if (tag == 8)
			return S_OK;

		if (tag == 6)
		{
			WORD revision;

			info->has_udf = TRUE;
			if (fx_iso_udf_revision_from_entity(sector + 216, &revision))
				return fx_iso_format_udf_revision(revision,
					info->udf_version, ARRAYSIZE(info->udf_version));
		}
	}

	return S_OK;
}

static HRESULT fx_iso_parse_udf_anchor(FX_ISO_READER *reader,
	FX_ISO_INFO *info)
{
	DWORD anchors[3];
	UINT anchor_count = 0;
	UINT index;

	anchors[anchor_count++] = 256;
	if (reader->sector_count > 256)
		anchors[anchor_count++] = reader->sector_count - 257U;
	if (reader->sector_count > 0)
		anchors[anchor_count++] = reader->sector_count - 1U;

	for (index = 0; index < anchor_count; index++)
	{
		DWORD main_lba = 0;
		DWORD main_length = 0;
		HRESULT hr;

		hr = fx_iso_try_udf_anchor(reader, anchors[index], &main_lba,
			&main_length);
		if (hr == S_OK)
		{
			hr = fx_iso_scan_udf_volume_sequence(reader, info, main_lba,
				main_length);
			if (FAILED(hr))
				return hr;
			if (info->udf_version[0] != L'\0')
				return S_OK;
		}
	}

	return S_OK;
}

static HRESULT fx_iso_parse_udf_vrs(FX_ISO_READER *reader, FX_ISO_INFO *info)
{
	BYTE sector[FX_ISO_SECTOR_SIZE];
	DWORD index;
	BYTE nsr_version = 0;

	for (index = 0; index < FX_ISO_MAX_VD_SECTORS; index++)
	{
		DWORD lba = 16U + index;
		HRESULT hr;

		hr = fx_iso_read_sector(reader, lba, sector);
		if (FAILED(hr))
			break;

		if (memcmp(sector + 1, "NSR02", 5) == 0)
		{
			info->has_udf = TRUE;
			nsr_version = 2;
		}
		else if (memcmp(sector + 1, "NSR03", 5) == 0)
		{
			info->has_udf = TRUE;
			nsr_version = 3;
		}
		else if (memcmp(sector + 1, "TEA01", 5) == 0)
		{
			break;
		}
	}

	if (info->has_udf)
	{
		HRESULT hr;

		hr = fx_iso_parse_udf_anchor(reader, info);
		if (FAILED(hr))
			return hr;

		if (info->udf_version[0] == L'\0')
		{
			if (nsr_version == 2)
				return StringCchCopyW(info->udf_version,
					ARRAYSIZE(info->udf_version), L"1.x");
			if (nsr_version == 3)
				return StringCchCopyW(info->udf_version,
					ARRAYSIZE(info->udf_version), L"2.x");
			return StringCchCopyW(info->udf_version,
				ARRAYSIZE(info->udf_version), L"Unknown");
		}
	}

	return S_OK;
}

static FX_ISO_FILENAME_MODE fx_iso_filename_mode(const FX_ISO_INFO *info)
{
	if (info->iso_enhanced || info->iso_max_name_len > 31)
		return FX_ISO_FILENAME_221;
	if (info->iso_needs_level2 || info->iso_max_name_len > 12)
		return FX_ISO_FILENAME_31;
	return FX_ISO_FILENAME_DOS;
}

static HRESULT fx_iso_parse(PCWSTR path, FX_ISO_INFO *info)
{
	FX_ISO_READER reader;
	HRESULT hr;

	ZeroMemory(info, sizeof(*info));
	hr = fx_iso_reader_open(path, &reader);
	if (FAILED(hr))
		return hr;

	hr = fx_iso_parse_volume_descriptors(&reader, info);
	if (FAILED(hr))
		goto done;

	if (info->has_iso9660)
	{
		hr = fx_iso_scan_directories(&reader, info);
		if (FAILED(hr))
			goto done;
	}

	hr = fx_iso_parse_udf_vrs(&reader, info);
	if (FAILED(hr))
		goto done;

	hr = fx_iso_parse_el_torito(&reader, info);
	if (FAILED(hr))
		goto done;

	fx_iso_detect_hybrid(&reader, info);

	if (!info->has_iso9660 && !info->has_joliet && !info->has_udf &&
		!info->has_el_torito)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}

done:
	fx_iso_reader_close(&reader);
	return hr;
}

static int fx_iso_dlg_x(HWND hwnd, int value)
{
	RECT rect = { 0, 0, value, 0 };

	MapDialogRect(hwnd, &rect);
	return rect.right;
}

static int fx_iso_dlg_y(HWND hwnd, int value)
{
	RECT rect = { 0, 0, 0, value };

	MapDialogRect(hwnd, &rect);
	return rect.bottom;
}

static void fx_iso_set_checkbox(HWND control, BOOL checked)
{
	SendMessageW(control, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED,
		0);
}

static HRESULT fx_iso_create_control(FX_ISO_VIEW *view, HWND *control,
	DWORD ex_style, PCWSTR class_name, PCWSTR text, DWORD style, int id)
{
	HINSTANCE instance;
	HFONT font;
	DWORD error;

	instance = (HINSTANCE)(ULONG_PTR)GetWindowLongPtrW(view->parent,
		GWLP_HINSTANCE);
	*control = CreateWindowExW(ex_style, class_name, text,
		style | WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, view->panel,
		(HMENU)(UINT_PTR)id, instance, NULL);
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

static HRESULT fx_iso_create_checkbox(FX_ISO_VIEW *view, HWND *control,
	PCWSTR text, int id)
{
	return fx_iso_create_control(view, control, 0, L"BUTTON", text,
		BS_CHECKBOX | WS_TABSTOP, id);
}

static HRESULT fx_iso_create_label(FX_ISO_VIEW *view, HWND *control,
	PCWSTR text, int id)
{
	return fx_iso_create_control(view, control, 0, L"STATIC", text,
		SS_LEFT, id);
}

static HRESULT fx_iso_create_edit(FX_ISO_VIEW *view, HWND *control,
	int id)
{
	return fx_iso_create_control(view, control, WS_EX_CLIENTEDGE, L"EDIT",
		L"", ES_AUTOHSCROLL | ES_READONLY | WS_TABSTOP, id);
}

static HRESULT fx_iso_create_combo(FX_ISO_VIEW *view, HWND *control,
	int id)
{
	return fx_iso_create_control(view, control, 0, L"COMBOBOX", L"",
		CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_TABSTOP | WS_VSCROLL, id);
}

static HRESULT fx_iso_create_controls(FX_ISO_VIEW *view)
{
	HRESULT hr;

	hr = fx_iso_create_label(view, &view->fs_section_label, L"Filesystems:",
		FX_ISO_ID_SECTION_FS);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->feature_iso9660, L"ISO9660",
		FX_ISO_ID_FEATURE_ISO9660);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->feature_joliet, L"Joliet",
		FX_ISO_ID_FEATURE_JOLIET);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->feature_udf, L"UDF",
		FX_ISO_ID_FEATURE_UDF);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->feature_rock_ridge,
		L"RockRidge", FX_ISO_ID_FEATURE_RR);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->feature_el_torito,
		L"El Torito", FX_ISO_ID_FEATURE_ELTORITO);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->feature_hybrid, L"Hybrid",
		FX_ISO_ID_FEATURE_HYBRID);
	if (FAILED(hr))
		return hr;

	hr = fx_iso_create_label(view, &view->iso_section_label, L"ISO9660:",
		FX_ISO_ID_SECTION_ISO9660);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_label(view, &view->iso_label, L"Filename Format",
		FX_ISO_ID_ISO_LABEL);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_edit(view, &view->iso_value, FX_ISO_ID_ISO_VALUE);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->iso_lowercase,
		L"Allow lowercase", FX_ISO_ID_ISO_LOWERCASE);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->iso_dos_charset,
		L"DOS Charset", FX_ISO_ID_ISO_DOS_CHARSET);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->iso_omit_version,
		L"Omit version", FX_ISO_ID_ISO_OMIT_VERSION);
	if (FAILED(hr))
		return hr;

	hr = fx_iso_create_label(view, &view->joliet_section_label, L"Joliet:",
		FX_ISO_ID_SECTION_JOLIET);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_label(view, &view->joliet_label,
		L"Filename Format", FX_ISO_ID_JOLIET_LABEL);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_edit(view, &view->joliet_value,
		FX_ISO_ID_JOLIET_VALUE);
	if (FAILED(hr))
		return hr;

	hr = fx_iso_create_label(view, &view->rr_section_label, L"RockRidge:",
		FX_ISO_ID_SECTION_ROCK_RIDGE);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->rr_rational,
		L"Rational-Rock", FX_ISO_ID_RR_RATIONAL);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->rr_reloc, L"Reloc-Dir",
		FX_ISO_ID_RR_RELOC);
	if (FAILED(hr))
		return hr;

	hr = fx_iso_create_label(view, &view->udf_section_label, L"UDF:",
		FX_ISO_ID_SECTION_UDF);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_label(view, &view->udf_label, L"Version",
		FX_ISO_ID_UDF_LABEL);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_edit(view, &view->udf_value, FX_ISO_ID_UDF_VALUE);
	if (FAILED(hr))
		return hr;

	hr = fx_iso_create_label(view, &view->boot_section_label, L"El Torito:",
		FX_ISO_ID_SECTION_EL_TORITO);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->boot_efi, L"EFI",
		FX_ISO_ID_BOOT_EFI);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->boot_bios, L"BIOS",
		FX_ISO_ID_BOOT_BIOS);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_checkbox(view, &view->boot_mac, L"Mac",
		FX_ISO_ID_BOOT_MAC);
	if (FAILED(hr))
		return hr;
	hr = fx_iso_create_label(view, &view->boot_label, L"Boot Image",
		FX_ISO_ID_BOOT_LABEL);
	if (FAILED(hr))
		return hr;
	return fx_iso_create_combo(view, &view->boot_combo,
		FX_ISO_ID_BOOT_COMBO);
}

static void fx_iso_populate_controls(FX_ISO_VIEW *view)
{
	const FX_ISO_INFO *info = &view->info;
	PCWSTR iso_filename;
	UINT index;

	switch (fx_iso_filename_mode(info))
	{
	case FX_ISO_FILENAME_221:
		iso_filename = L"Max(221)";
		break;
	case FX_ISO_FILENAME_31:
		iso_filename = L"Windows/Unix(31)";
		break;
	default:
		iso_filename = L"DOS(8.3)";
		break;
	}

	fx_iso_set_checkbox(view->feature_iso9660, info->has_iso9660);
	fx_iso_set_checkbox(view->feature_joliet, info->has_joliet);
	fx_iso_set_checkbox(view->feature_udf, info->has_udf);
	fx_iso_set_checkbox(view->feature_rock_ridge, info->has_rock_ridge);
	fx_iso_set_checkbox(view->feature_el_torito, info->has_el_torito);
	fx_iso_set_checkbox(view->feature_hybrid, info->is_hybrid);
	fx_iso_set_checkbox(view->iso_lowercase, info->iso_lowercase);
	fx_iso_set_checkbox(view->iso_dos_charset, info->iso_dos_charset);
	fx_iso_set_checkbox(view->iso_omit_version, info->iso_omit_version);
	fx_iso_set_checkbox(view->rr_rational, info->rr_rational);
	fx_iso_set_checkbox(view->rr_reloc, info->rr_reloc);
	fx_iso_set_checkbox(view->boot_efi, info->boot_efi);
	fx_iso_set_checkbox(view->boot_bios, info->boot_bios);
	fx_iso_set_checkbox(view->boot_mac, info->boot_mac);

	SetWindowTextW(view->iso_value, iso_filename);
	SetWindowTextW(view->joliet_value,
		info->joliet_extended ? L"Extended(110)" : L"Standard(64)");
	SetWindowTextW(view->udf_value,
		info->udf_version[0] != L'\0' ? info->udf_version : L"Unknown");

	SendMessageW(view->boot_combo, CB_RESETCONTENT, 0, 0);
	for (index = 0; index < info->boot_image_count; index++)
	{
		SendMessageW(view->boot_combo, CB_ADDSTRING, 0,
			(LPARAM)info->boot_images[index].text);
	}
	if (info->boot_image_count == 0)
	{
		SendMessageW(view->boot_combo, CB_ADDSTRING, 0,
			(LPARAM)L"Boot catalog present");
	}
	SendMessageW(view->boot_combo, CB_SETCURSEL, 0, 0);
}

static void fx_iso_show(HWND control, BOOL show)
{
	ShowWindow(control, show ? SW_SHOW : SW_HIDE);
}

static void fx_iso_move(HWND control, int x, int y, int width, int height)
{
	MoveWindow(control, x, y, width, height, TRUE);
}

static void fx_iso_layout_top_checks(FX_ISO_VIEW *view, int width,
	int *y, int checkbox_height, int label_height, int gap_y)
{
	int col_width = width / 3;
	int third_x = col_width * 2;

	if (col_width < fx_iso_dlg_x(view->parent, 52))
		col_width = width / 3;

	fx_iso_move(view->fs_section_label, 0, *y - view->scroll_pos, width,
		label_height);
	*y += label_height + gap_y;

	fx_iso_move(view->feature_iso9660, 0, *y - view->scroll_pos,
		col_width, checkbox_height);
	fx_iso_move(view->feature_joliet, col_width, *y - view->scroll_pos,
		col_width, checkbox_height);
	fx_iso_move(view->feature_udf, third_x, *y - view->scroll_pos,
		width - third_x, checkbox_height);
	*y += checkbox_height + gap_y;

	fx_iso_move(view->feature_rock_ridge, 0, *y - view->scroll_pos,
		col_width, checkbox_height);
	fx_iso_move(view->feature_el_torito, col_width, *y - view->scroll_pos,
		col_width, checkbox_height);
	fx_iso_move(view->feature_hybrid, third_x, *y - view->scroll_pos,
		width - third_x, checkbox_height);
	*y += checkbox_height + gap_y * 2;
}

static void fx_iso_layout_section_label(FX_ISO_VIEW *view, HWND label,
	int width, int *y, int label_height, int gap_y)
{
	fx_iso_move(label, 0, *y - view->scroll_pos, width, label_height);
	*y += label_height + gap_y;
}

static void fx_iso_layout_label_value(FX_ISO_VIEW *view, HWND label,
	HWND value, int width, int *y, int label_width, int gap_x,
	int label_height, int edit_height, int gap_y)
{
	int label_y = *y + (edit_height - label_height) / 2;
	int value_x = label_width + gap_x;

	fx_iso_move(label, 0, label_y - view->scroll_pos, label_width,
		label_height);
	fx_iso_move(value, value_x, *y - view->scroll_pos, width - value_x,
		edit_height);
	*y += edit_height + gap_y;
}

static void fx_iso_layout_controls_once(FX_ISO_VIEW *view)
{
	const FX_ISO_INFO *info = &view->info;
	RECT client;
	int width;
	int y = 0;
	int checkbox_height;
	int label_height;
	int edit_height;
	int combo_height;
	int gap_x;
	int gap_y;
	int section_gap;
	int label_width;
	int col_width;
	int third_x;

	GetClientRect(view->panel, &client);
	width = client.right - client.left;
	if (width < 1)
		width = 1;

	checkbox_height = fx_iso_dlg_y(view->parent, 10);
	label_height = fx_iso_dlg_y(view->parent, 8);
	edit_height = fx_iso_dlg_y(view->parent, 14);
	combo_height = fx_iso_dlg_y(view->parent, 80);
	gap_x = fx_iso_dlg_x(view->parent, 5);
	gap_y = fx_iso_dlg_y(view->parent, 4);
	section_gap = fx_iso_dlg_y(view->parent, 6);
	label_width = fx_iso_dlg_x(view->parent, 68);
	col_width = width / 3;
	third_x = col_width * 2;

	fx_iso_layout_top_checks(view, width, &y, checkbox_height, label_height,
		gap_y);

	fx_iso_show(view->iso_section_label, info->has_iso9660);
	fx_iso_show(view->iso_label, info->has_iso9660);
	fx_iso_show(view->iso_value, info->has_iso9660);
	fx_iso_show(view->iso_lowercase, info->has_iso9660);
	fx_iso_show(view->iso_dos_charset, info->has_iso9660);
	fx_iso_show(view->iso_omit_version, info->has_iso9660);
	if (info->has_iso9660)
	{
		fx_iso_layout_section_label(view, view->iso_section_label, width,
			&y, label_height, gap_y);
		fx_iso_layout_label_value(view, view->iso_label, view->iso_value,
			width, &y, label_width, gap_x, label_height, edit_height,
			gap_y);
		fx_iso_move(view->iso_lowercase, 0, y - view->scroll_pos,
			col_width, checkbox_height);
		fx_iso_move(view->iso_dos_charset, col_width, y - view->scroll_pos,
			col_width, checkbox_height);
		fx_iso_move(view->iso_omit_version, third_x, y - view->scroll_pos,
			width - third_x, checkbox_height);
		y += checkbox_height + section_gap;
	}

	fx_iso_show(view->joliet_section_label, info->has_joliet);
	fx_iso_show(view->joliet_label, info->has_joliet);
	fx_iso_show(view->joliet_value, info->has_joliet);
	if (info->has_joliet)
	{
		fx_iso_layout_section_label(view, view->joliet_section_label,
			width, &y, label_height, gap_y);
		fx_iso_layout_label_value(view, view->joliet_label,
			view->joliet_value, width, &y, label_width, gap_x,
			label_height, edit_height, section_gap);
	}

	fx_iso_show(view->rr_section_label, info->has_rock_ridge);
	fx_iso_show(view->rr_rational, info->has_rock_ridge);
	fx_iso_show(view->rr_reloc, info->has_rock_ridge);
	if (info->has_rock_ridge)
	{
		fx_iso_layout_section_label(view, view->rr_section_label, width,
			&y, label_height, gap_y);
		fx_iso_move(view->rr_rational, 0, y - view->scroll_pos,
			col_width, checkbox_height);
		fx_iso_move(view->rr_reloc, col_width, y - view->scroll_pos,
			col_width, checkbox_height);
		y += checkbox_height + section_gap;
	}

	fx_iso_show(view->udf_section_label, info->has_udf);
	fx_iso_show(view->udf_label, info->has_udf);
	fx_iso_show(view->udf_value, info->has_udf);
	if (info->has_udf)
	{
		fx_iso_layout_section_label(view, view->udf_section_label, width,
			&y, label_height, gap_y);
		fx_iso_layout_label_value(view, view->udf_label, view->udf_value,
			width, &y, label_width, gap_x, label_height, edit_height,
			section_gap);
	}

	fx_iso_show(view->boot_section_label, info->has_el_torito);
	fx_iso_show(view->boot_efi, info->has_el_torito);
	fx_iso_show(view->boot_bios, info->has_el_torito);
	fx_iso_show(view->boot_mac, info->has_el_torito);
	fx_iso_show(view->boot_label, info->has_el_torito);
	fx_iso_show(view->boot_combo, info->has_el_torito);
	if (info->has_el_torito)
	{
		int label_y;
		int value_x;

		fx_iso_layout_section_label(view, view->boot_section_label, width,
			&y, label_height, gap_y);
		fx_iso_move(view->boot_efi, 0, y - view->scroll_pos, col_width,
			checkbox_height);
		fx_iso_move(view->boot_bios, col_width, y - view->scroll_pos,
			col_width, checkbox_height);
		fx_iso_move(view->boot_mac, third_x, y - view->scroll_pos,
			width - third_x, checkbox_height);
		y += checkbox_height + gap_y;

		label_y = y + (edit_height - label_height) / 2;
		value_x = label_width + gap_x;
		fx_iso_move(view->boot_label, 0, label_y - view->scroll_pos,
			label_width, label_height);
		fx_iso_move(view->boot_combo, value_x, y - view->scroll_pos,
			width - value_x, combo_height);
		y += edit_height + gap_y;
	}

	view->content_height = y;
}

static void fx_iso_update_scrollbar(FX_ISO_VIEW *view)
{
	RECT client;
	SCROLLINFO info;
	int page;
	int max_scroll;

	GetClientRect(view->panel, &client);
	page = client.bottom - client.top;
	if (page < 1)
		page = 1;

	max_scroll = view->content_height - page;
	if (max_scroll < 0)
		max_scroll = 0;
	if (view->scroll_pos > max_scroll)
		view->scroll_pos = max_scroll;
	if (view->scroll_pos < 0)
		view->scroll_pos = 0;

	ShowScrollBar(view->panel, SB_VERT, max_scroll > 0);

	ZeroMemory(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
	info.nMin = 0;
	info.nMax = view->content_height > 0 ? view->content_height - 1 : 0;
	info.nPage = (UINT)page;
	info.nPos = view->scroll_pos;
	SetScrollInfo(view->panel, SB_VERT, &info, TRUE);
}

static void fx_iso_layout_controls(FX_ISO_VIEW *view)
{
	int old_scroll;

	old_scroll = view->scroll_pos;
	fx_iso_layout_controls_once(view);
	fx_iso_update_scrollbar(view);
	if (old_scroll != view->scroll_pos)
		fx_iso_layout_controls_once(view);
}

static void fx_iso_scroll_to(FX_ISO_VIEW *view, int position)
{
	RECT client;
	int page;
	int max_scroll;

	GetClientRect(view->panel, &client);
	page = client.bottom - client.top;
	if (page < 1)
		page = 1;

	max_scroll = view->content_height - page;
	if (max_scroll < 0)
		max_scroll = 0;
	if (position < 0)
		position = 0;
	if (position > max_scroll)
		position = max_scroll;
	if (position == view->scroll_pos)
		return;

	view->scroll_pos = position;
	SendMessageW(view->panel, WM_SETREDRAW, FALSE, 0);
	fx_iso_layout_controls(view);
	SendMessageW(view->panel, WM_SETREDRAW, TRUE, 0);
	RedrawWindow(view->panel, NULL, NULL,
		RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

static LRESULT CALLBACK fx_iso_panel_proc(HWND hwnd, UINT message,
	WPARAM wparam, LPARAM lparam)
{
	FX_ISO_VIEW *view = (FX_ISO_VIEW *)GetWindowLongPtrW(hwnd,
		GWLP_USERDATA);

	if (!view)
		return DefWindowProcW(hwnd, message, wparam, lparam);

	switch (message)
	{
	case WM_VSCROLL:
	{
		SCROLLINFO info;
		int position = view->scroll_pos;
		int line = fx_iso_dlg_y(view->parent, 10);

		ZeroMemory(&info, sizeof(info));
		info.cbSize = sizeof(info);
		info.fMask = SIF_ALL;
		GetScrollInfo(hwnd, SB_VERT, &info);

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
			position = view->content_height;
			break;
		default:
			break;
		}

		fx_iso_scroll_to(view, position);
		return 0;
	}
	case WM_MOUSEWHEEL:
	{
		int delta = (short)HIWORD(wparam);
		int line = fx_iso_dlg_y(view->parent, 30);

		fx_iso_scroll_to(view,
			view->scroll_pos - MulDiv(delta, line, WHEEL_DELTA));
		return 0;
	}
	case WM_NCHITTEST:
	case WM_NCLBUTTONDOWN:
		return DefWindowProcW(hwnd, message, wparam, lparam);
	case WM_CTLCOLORSTATIC:
		return SendMessageW(view->parent, message, wparam, lparam);
	case WM_NCDESTROY:
		SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
		break;
	default:
		break;
	}

	return CallWindowProcW(view->old_panel_proc, hwnd, message, wparam,
		lparam);
}

static void fx_iso_destroy(void *context)
{
	FX_ISO_VIEW *view = (FX_ISO_VIEW *)context;

	if (view->panel)
		DestroyWindow(view->panel);
	HeapFree(GetProcessHeap(), 0, view);
}

static HRESULT fx_iso_create(HWND parent, PCWSTR path, void **context)
{
	FX_ISO_VIEW *view;
	HINSTANCE instance;
	HFONT font;
	DWORD error;
	HRESULT hr;

	*context = NULL;
	view = (FX_ISO_VIEW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		sizeof(*view));
	if (!view)
		return E_OUTOFMEMORY;
	view->parent = parent;

	hr = fx_iso_parse(path, &view->info);
	if (FAILED(hr))
		goto fail;

	instance = (HINSTANCE)(ULONG_PTR)GetWindowLongPtrW(parent,
		GWLP_HINSTANCE);
	view->panel = CreateWindowExW(WS_EX_CONTROLPARENT, L"STATIC", L"",
		WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_VSCROLL, 0, 0, 0, 0,
		parent, (HMENU)(UINT_PTR)FX_ISO_ID_PANEL, instance, NULL);
	if (!view->panel)
	{
		error = GetLastError();
		if (error == ERROR_SUCCESS)
			error = ERROR_NOT_ENOUGH_MEMORY;
		hr = HRESULT_FROM_WIN32(error);
		goto fail;
	}

	font = (HFONT)SendMessageW(parent, WM_GETFONT, 0, 0);
	if (font)
		SendMessageW(view->panel, WM_SETFONT, (WPARAM)font, FALSE);

	SetWindowLongPtrW(view->panel, GWLP_USERDATA, (LONG_PTR)view);
	view->old_panel_proc = (WNDPROC)(LONG_PTR)SetWindowLongPtrW(view->panel,
		GWLP_WNDPROC, (LONG_PTR)fx_iso_panel_proc);

	hr = fx_iso_create_controls(view);
	if (FAILED(hr))
		goto fail;

	fx_iso_populate_controls(view);

	*context = view;
	return S_OK;

fail:
	fx_iso_destroy(view);
	return hr;
}

static void fx_iso_layout(void *context, const RECT *bounds)
{
	FX_ISO_VIEW *view = (FX_ISO_VIEW *)context;
	int width;
	int height;

	width = bounds->right - bounds->left;
	height = bounds->bottom - bounds->top;
	if (width < 0)
		width = 0;
	if (height < 0)
		height = 0;

	MoveWindow(view->panel, bounds->left, bounds->top, width, height, TRUE);
	fx_iso_layout_controls(view);
}

const FX_EXTENSION_HANDLER fx_extension_iso_handler =
{
	L".iso",
	L"ISO",
	fx_iso_create,
	fx_iso_layout,
	fx_iso_destroy,
	NULL
};
