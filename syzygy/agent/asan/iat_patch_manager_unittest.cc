// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "syzygy/agent/asan/iat_patch_manager.h"

#include <windows.h>

#include "gtest/gtest.h"
#include "base/win/pe_image.h"
#include "syzygy/pe/unittest_util.h"

namespace agent {
namespace asan {

namespace {

typedef int (*ExportDllFunctionPointer)();

// Dummy function. We use only its address.
int patched_function1() {
  return 0;
}

// Dummy function. We use only its address.
int patched_function3() {
  return 0;
}

const char kExportDll[] = "export_dll.dll";

const IATPatchManager::IATRedirectRule kTestRedirectEntries[] = {
  { kExportDll, "function1", &patched_function1 },
  { kExportDll, "function3", &patched_function3 },
  { nullptr, nullptr, nullptr }
};

bool ImportRedirectChecker(const base::win::PEImage &image,
                           LPCSTR module,
                           DWORD ordinal,
                           LPCSTR name,
                           DWORD hint,
                           PIMAGE_THUNK_DATA iat,
                           PVOID cookie) {
  DCHECK(nullptr != cookie);
  size_t * const redirects_found =
      reinterpret_cast<size_t*>(cookie);

  if (module != nullptr && ::strcmp(kExportDll, module) == 0) {
    if (name != nullptr && ::strcmp(name, "function1") == 0) {
      EXPECT_EQ(iat->u1.Function, reinterpret_cast<uint32>(&patched_function1));
      ++*redirects_found;
    }
    if (name != nullptr && ::strcmp(name, "function3") == 0) {
      EXPECT_EQ(iat->u1.Function, reinterpret_cast<uint32>(&patched_function3));
      ++*redirects_found;
    }
  }

  return true;
}

}  // namespace

TEST(IATPatchManagerTest, TestDll) {
  base::FilePath test_dll_path =
      testing::GetExeRelativePath(L"test_dll.dll");
  testing::ScopedHMODULE test_dll(
      ::LoadLibrary(test_dll_path.value().c_str()));
  ASSERT_NE(nullptr, static_cast<HMODULE>(test_dll));

  // test_dll.dll imports functions from export_dll.dll. Redirect those imports.
  IATPatchManager iat_manager;
  size_t redirect_count =
      iat_manager.RedirectImports(test_dll, kTestRedirectEntries);
  ASSERT_EQ(2U, redirect_count);

  // Checks if the imports are redirected in the IAT.
  size_t redirects_found = 0U;
  base::win::PEImage test_dll_image(test_dll);
  test_dll_image.EnumAllImports(&ImportRedirectChecker,
                                &redirects_found);
  // We must find both redirects. We check correctness inside the callback.
  EXPECT_EQ(2U, redirects_found);
}

}  // namespace asan
}  // namespace agent
