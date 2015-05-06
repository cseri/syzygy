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

#include "syzygy/agent/asan/hot_patching_asan_iat_redirects.h"

#include "syzygy/agent/asan/asan_crt_interceptors.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"

namespace agent {
namespace asan {

namespace {

const char kKernel32[] = "kernel32.dll";

// TODO(cseri): Use own DLL name instead of hardcoding the default name.
const char kSyzyAsanHp[] = "syzyasan_hp.dll";

}  // namespace

IATPatchManager::IATRedirectRule kHotPatchingAsanIATRedirects[] = {
  // Heap related kernel32 functions.
  { kKernel32, "HeapCreate", &asan_HeapCreate },
  { kKernel32, "HeapDestroy", &asan_HeapDestroy },
  { kKernel32, "HeapAlloc", &asan_HeapAlloc },
  { kKernel32, "HeapReAlloc", &asan_HeapReAlloc },
  { kKernel32, "HeapFree", &asan_HeapFree },
  { kKernel32, "HeapSize", &asan_HeapSize },
  { kKernel32, "HeapValidate", &asan_HeapValidate },
  { kKernel32, "HeapCompact", &asan_HeapCompact },
  { kKernel32, "HeapLock", &asan_HeapLock },
  { kKernel32, "HeapUnlock", &asan_HeapUnlock },
  { kKernel32, "HeapWalk", &asan_HeapWalk },
  { kKernel32, "HeapSetInformation", &asan_HeapSetInformation },
  { kKernel32, "HeapQueryInformation", &asan_HeapQueryInformation },

  // CRT intercepts.
  { kSyzyAsanHp, "hp_asan_memchr", &asan_memchr },
  { kSyzyAsanHp, "hp_asan_memcpy", &asan_memcpy },
  { kSyzyAsanHp, "hp_asan_memmove", &asan_memmove },
  { kSyzyAsanHp, "hp_asan_memset", &asan_memset },
  { kSyzyAsanHp, "hp_asan_strcmp", &asan_strcmp },
  { kSyzyAsanHp, "hp_asan_strcspn", &asan_strcspn },
  { kSyzyAsanHp, "hp_asan_strlen", &asan_strlen },
  { kSyzyAsanHp, "hp_asan_strncat", &asan_strncat },
  { kSyzyAsanHp, "hp_asan_strncpy", &asan_strncpy },
  { kSyzyAsanHp, "hp_asan_strpbrk", &asan_strpbrk },
  { kSyzyAsanHp, "hp_asan_strrchr", &asan_strrchr },
  { kSyzyAsanHp, "hp_asan_strspn", &asan_strspn },
  { kSyzyAsanHp, "hp_asan_strstr", &asan_strstr },
  { kSyzyAsanHp, "hp_asan_wcschr", &asan_wcschr },
  { kSyzyAsanHp, "hp_asan_wcsrchr", &asan_wcsrchr },
  { kSyzyAsanHp, "hp_asan_wcsstr", &asan_wcsstr },

  // TODO(cseri): Redirect system interceptors.

  // Terminating entry.
  { nullptr, nullptr, nullptr }
};

}  // namespace asan
}  // namespace agent
