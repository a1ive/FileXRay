/* SPDX-License-Identifier: LGPL-3.0-or-later */

#pragma once

#define QUOTE_(x) #x
#define QUOTE(x) QUOTE_(x)

#define FX_MAJOR_VERSION 0
#define FX_MINOR_VERSION 0
#define FX_MICRO_VERSION 1
#define FX_BUILD_VERSION 0

#define FX_VERSION      FX_MAJOR_VERSION,FX_MINOR_VERSION,FX_MICRO_VERSION,FX_BUILD_VERSION
#define FX_VERSION_STR  QUOTE(FX_MAJOR_VERSION.FX_MINOR_VERSION.FX_MICRO_VERSION.FX_BUILD_VERSION)

#define FX_COMPANY      "A1ive"
#define FX_COPYRIGHT    "Copyright (c) 2026 A1ive"
#define FX_FILEDESC     "FileXRay Shell Property Sheet Handler"

#define FX_DLL          "FileXRay"
#define FX_PRODUCT      FX_DLL
#define FX_INTERNALNAME FX_DLL
#define FX_ORIGINALNAME FX_DLL ".dll"
