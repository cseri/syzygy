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

#include <new>

#include "base/win/iat_patch_function.h"

namespace agent {
namespace asan {

IATPatchManager::IATPatchManager() { }

IATPatchManager::~IATPatchManager() { }

size_t IATPatchManager::RedirectImports(
    HMODULE module,
    const IATRedirectRule* entries) {
  size_t redirect_count = 0;

  for (const IATRedirectRule* current_entry = entries;
       current_entry->import_name != nullptr;
       ++current_entry) {
    // The |IATPatchFunction| object tries to revert the IAT Patch in its
    // destructor. To circumvent calling its destructor we use placement new
    // to allocate the object.
    // TODO(cseri): Please clean this up.
    uint8 buffer[sizeof(base::win::IATPatchFunction)];
    base::win::IATPatchFunction* iat_patcher =
        new (static_cast<void*>(buffer)) base::win::IATPatchFunction();

    // Patch the IAT entry.
    uint32 error = iat_patcher->PatchFromModule(
        module,
        current_entry->import_module_name,
        current_entry->import_name,
        current_entry->target_function);

    // NOTE: We don't fail on error because the IAT redirect also fails if the
    // module does not import a specific function.
    if (error == NO_ERROR) {
      ++redirect_count;
    }
  }

  return redirect_count;
}

}  // namespace asan
}  // namespace agent
