# FileXRay

FileXRay is a Windows Shell Property Sheet Handler. It adds a `FileXRay` tab to the file Properties dialog for quick inspection from Explorer.

## Features

- Detects file types with an embedded `file`/`libmagic` database.
- Calculates and copies MD5, SHA1, SHA256, SHA512, CRC32, and CRC64 hashes.
- Adds extra views for selected formats:
  - `.exe`: imported DLL dependencies.
  - `.dll`: exported functions.
  - `.ico`: icon previews.
  - `.efi`: image base and SBAT data.
  - `.iso`: ISO9660/UDF details.

## Download

- [x64 Build](https://nightly.link/a1ive/FileXRay/workflows/msbuild/master/FileXRay-x64.zip)
- [x86 Build](https://nightly.link/a1ive/FileXRay/workflows/msbuild/master/FileXRay-x86.zip)

Use the build that matches your Windows architecture. On 64-bit Windows, use the x64 package; registering the x86 DLL through SysWOW64 is not supported.

## Install

1. Download and extract the package to a folder you plan to keep.
2. Run `install.bat` as **Administrator**.
3. Reopen any file Properties windows and select the `FileXRay` tab.

To uninstall, run `uninstall.bat` as **Administrator** before deleting the folder.

## License

FileXRay is licensed under `LGPL-3.0-or-later`; see [LICENSE](LICENSE).

## Acknowledgements

- [file](https://github.com/file/file)
- [zstd](https://github.com/facebook/zstd)
- [systeminformer](https://github.com/winsiderss/systeminformer)
