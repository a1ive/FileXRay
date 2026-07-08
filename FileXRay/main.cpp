/* SPDX-License-Identifier: LGPL-3.0-or-later */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <new>

#include "filetype.h"
#include "pagectrl.h"
#include "registration.h"

static HINSTANCE g_filexray_instance;
static volatile LONG g_filexray_dll_refs;

extern "C" void fx_module_add_ref(void)
{
	InterlockedIncrement(&g_filexray_dll_refs);
}

extern "C" void fx_module_release(void)
{
	InterlockedDecrement(&g_filexray_dll_refs);
}

static const CLSID CLSID_FileXRayPropertySheet =
{
	0xc2d21996, 0x0f0e, 0x4c9e,
	{ 0xb7, 0x94, 0x47, 0xa8, 0xb7, 0x7c, 0x96, 0x17 }
};

class FileXRayExtension : public IShellExtInit, public IShellPropSheetExt
{
public:
	FileXRayExtension() :
		m_ref_count(1),
		m_path(NULL)
	{
		InterlockedIncrement(&g_filexray_dll_refs);
	}

	~FileXRayExtension()
	{
		if (m_path)
			HeapFree(GetProcessHeap(), 0, m_path);
		InterlockedDecrement(&g_filexray_dll_refs);
	}

	IFACEMETHODIMP QueryInterface(REFIID iid, void **object)
	{
		if (!object)
			return E_POINTER;

		*object = NULL;

		if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, IID_IShellExtInit))
			*object = static_cast<IShellExtInit *>(this);
		else if (IsEqualIID(iid, IID_IShellPropSheetExt))
			*object = static_cast<IShellPropSheetExt *>(this);
		else
			return E_NOINTERFACE;

		AddRef();
		return S_OK;
	}

	IFACEMETHODIMP_(ULONG) AddRef()
	{
		return (ULONG)InterlockedIncrement(&m_ref_count);
	}

	IFACEMETHODIMP_(ULONG) Release()
	{
		ULONG refs = (ULONG)InterlockedDecrement(&m_ref_count);

		if (refs == 0)
			delete this;

		return refs;
	}

	IFACEMETHODIMP Initialize(PCIDLIST_ABSOLUTE pidl_folder, IDataObject *data_object, HKEY key_prog_id)
	{
		FORMATETC format = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
		STGMEDIUM medium;
		HRESULT hr;
		UINT count;
		UINT length;
		WCHAR *path = NULL;

		UNREFERENCED_PARAMETER(pidl_folder);
		UNREFERENCED_PARAMETER(key_prog_id);

		if (!data_object)
			return E_INVALIDARG;

		ZeroMemory(&medium, sizeof(medium));

		hr = data_object->GetData(&format, &medium);
		if (FAILED(hr))
			goto fail;

		count = DragQueryFileW((HDROP)medium.hGlobal, 0xffffffffU, NULL, 0);
		if (count != 1)
		{
			hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
			goto fail;
		}

		length = DragQueryFileW((HDROP)medium.hGlobal, 0, NULL, 0);
		if (length == 0)
		{
			hr = E_FAIL;
			goto fail;
		}

		path = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, ((size_t)length + 1U) * sizeof(WCHAR));
		if (!path)
		{
			hr = E_OUTOFMEMORY;
			goto fail;
		}

		if (DragQueryFileW((HDROP)medium.hGlobal, 0, path, length + 1U) == 0)
		{
			hr = E_FAIL;
			goto fail;
		}

		if (m_path)
			HeapFree(GetProcessHeap(), 0, m_path);
		m_path = path;
		path = NULL;
		hr = S_OK;

	fail:
		if (path)
			HeapFree(GetProcessHeap(), 0, path);
		if (medium.tymed != TYMED_NULL)
			ReleaseStgMedium(&medium);

		return hr;
	}

	IFACEMETHODIMP AddPages(LPFNADDPROPSHEETPAGE add_page, LPARAM lparam)
	{
		if (!m_path)
			return E_FAIL;

		return fx_add_property_sheet_page(g_filexray_instance, m_path, add_page, lparam);
	}

	IFACEMETHODIMP ReplacePage(UINT page_id, LPFNADDPROPSHEETPAGE replace_with, LPARAM lparam)
	{
		UNREFERENCED_PARAMETER(page_id);
		UNREFERENCED_PARAMETER(replace_with);
		UNREFERENCED_PARAMETER(lparam);

		return E_NOTIMPL;
	}

private:
	LONG m_ref_count;
	WCHAR *m_path;
};

class FileXRayClassFactory : public IClassFactory
{
public:
	FileXRayClassFactory() :
		m_ref_count(1)
	{
		InterlockedIncrement(&g_filexray_dll_refs);
	}

	~FileXRayClassFactory()
	{
		InterlockedDecrement(&g_filexray_dll_refs);
	}

	IFACEMETHODIMP QueryInterface(REFIID iid, void **object)
	{
		if (!object)
			return E_POINTER;

		*object = NULL;

		if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, IID_IClassFactory))
			*object = static_cast<IClassFactory *>(this);
		else
			return E_NOINTERFACE;

		AddRef();
		return S_OK;
	}

	IFACEMETHODIMP_(ULONG) AddRef()
	{
		return (ULONG)InterlockedIncrement(&m_ref_count);
	}

	IFACEMETHODIMP_(ULONG) Release()
	{
		ULONG refs = (ULONG)InterlockedDecrement(&m_ref_count);

		if (refs == 0)
			delete this;

		return refs;
	}

	IFACEMETHODIMP CreateInstance(IUnknown *outer, REFIID iid, void **object)
	{
		HRESULT hr;
		FileXRayExtension *extension;

		if (outer)
			return CLASS_E_NOAGGREGATION;
		if (!object)
			return E_POINTER;

		*object = NULL;

		extension = new (std::nothrow) FileXRayExtension();
		if (!extension)
			return E_OUTOFMEMORY;

		hr = extension->QueryInterface(iid, object);
		extension->Release();

		return hr;
	}

	IFACEMETHODIMP LockServer(BOOL lock)
	{
		if (lock)
			InterlockedIncrement(&g_filexray_dll_refs);
		else
			InterlockedDecrement(&g_filexray_dll_refs);

		return S_OK;
	}

private:
	LONG m_ref_count;
};

extern "C" BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		g_filexray_instance = instance;
		DisableThreadLibraryCalls(instance);
	}
	else if (reason == DLL_PROCESS_DETACH && !reserved)
	{
		fx_filetype_shutdown();
	}

	return TRUE;
}

extern "C" STDAPI DllCanUnloadNow(void)
{
	return InterlockedCompareExchange(&g_filexray_dll_refs, 0, 0) == 0 ? S_OK : S_FALSE;
}

extern "C" STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **object)
{
	HRESULT hr;
	FileXRayClassFactory *factory;

	if (!object)
		return E_POINTER;

	*object = NULL;

	if (!IsEqualCLSID(clsid, CLSID_FileXRayPropertySheet))
		return CLASS_E_CLASSNOTAVAILABLE;

	factory = new (std::nothrow) FileXRayClassFactory();
	if (!factory)
		return E_OUTOFMEMORY;

	hr = factory->QueryInterface(iid, object);
	factory->Release();

	return hr;
}

extern "C" STDAPI DllRegisterServer(void)
{
	HRESULT hr;
	WCHAR module_path[MAX_PATH];
	DWORD length;

	length = GetModuleFileNameW(g_filexray_instance, module_path, ARRAYSIZE(module_path));
	if (length == 0)
		return HRESULT_FROM_WIN32(GetLastError());
	if (length == ARRAYSIZE(module_path))
		return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

	hr = fx_register_server(&CLSID_FileXRayPropertySheet, module_path);
	if (FAILED(hr))
		fx_unregister_server(&CLSID_FileXRayPropertySheet);

	return hr;
}

extern "C" STDAPI DllUnregisterServer(void)
{
	return fx_unregister_server(&CLSID_FileXRayPropertySheet);
}
