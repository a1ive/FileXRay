/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "extensions.h"

#include <wchar.h>

static const FX_EXTENSION_HANDLER *const fx_extension_handlers[] =
{
	&fx_extension_dll_handler,
	&fx_extension_efi_handler,
	&fx_extension_exe_handler,
};

const FX_EXTENSION_HANDLER *fx_extension_find(PCWSTR extension)
{
	size_t index;

	for (index = 0; index < ARRAYSIZE(fx_extension_handlers); index++)
	{
		if (_wcsicmp(extension, fx_extension_handlers[index]->extension) == 0)
			return fx_extension_handlers[index];
	}

	return NULL;
}
