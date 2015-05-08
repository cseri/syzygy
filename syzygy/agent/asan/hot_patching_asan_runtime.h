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
//
// The main class of the hot patching Asan runtime library.
//
// A single instance of this class is created by the DllMain of module of
// the hot patching Asan runtime library and can be accessed from anywhere
// via |HotPatchingAsanRuntime::runtime()|.

#ifndef SYZYGY_AGENT_ASAN_HOT_PATCHING_ASAN_RUNTIME_H_
#define SYZYGY_AGENT_ASAN_HOT_PATCHING_ASAN_RUNTIME_H_

#include <unordered_set>
#include <string>
#include <unordered_set>

#include <windows.h>
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/memory/singleton.h"
#include "syzygy/agent/asan/hot_patching_asan_iat_redirects.h"
#include "syzygy/agent/asan/iat_patch_manager.h"
#include "syzygy/agent/common/entry_frame.h"
#include "syzygy/pe/hot_patching_writer.h"

namespace agent {
namespace asan {

class AsanLogger;
class AsanRuntime;

class HotPatchingAsanRuntime {
 public:
  // Hot patching Asan transform instruments the entry point of the modules so
  // that this function is called before each DllMain call of the instrumented
  // modules. At this point the code of the hot patching runtime module is
  // already loaded so, this is a good place to do hot patching.
  // @param entry_frame A frame containing the return address and the parameters
  //     of the original DllMain function.
  static void WINAPI DllMainEntryHook(agent::EntryFrame* entry_frame,
                                      FuncAddr function);

  // Access to the singleton class.
  // @returns the hot patching Asan runtime.
  static HotPatchingAsanRuntime* GetInstance() {
    return Singleton<HotPatchingAsanRuntime>::get();
  }

  // Activates the hot patching Asan mode on a given module.
  // @param instance The handle to the module.
  // NOTE: The current implementation of this function is not thread-safe. This
  //     is not a problem for now, because we call this function under the
  //     loader lock.
  bool HotPatch(HINSTANCE instance);

  // Called by the process attach in the DllMain of hot patching Asan
  // instrumented modules.
  // @param instance The handle to the module being attached to the process.
  // NOTE: The entry thunk transform instruments more entry points of
  //     modules, therefore this function may be called multiple times per
  //     module.
  void ProcessAttach(HINSTANCE instance);

  // Called by the process detach in the DllMain of hot patching Asan
  // instrumented modules.
  // @param instance The handle to the module being detached from the process.
  // NOTE: The entry thunk transform instruments more entry points of
  //     modules, therefore this function may be called multiple times per
  //     module.
  void ProcessDetach(HINSTANCE instance);

  // Sets up the hot patching Asan runtime.
  void SetUp();

  // Gets the set of modules that have already been hot patched.
  // @returns a set containing the handles of the hot patched modules.
  const std::unordered_set<HMODULE>& hot_patched_modules() {
    return hot_patched_modules_;
  }

  // Gets a logger.
  AsanLogger* logger() {
    DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger_.get());
    return logger_.get();
  }

 protected:
  void SetUpLogger();

  // The shared logger instance that will be used to report errors and runtime
  // information.
  scoped_ptr<AsanLogger> logger_;

  // Set of modules that have already been hot patched. We don't want to hot
  // patch the same module twice.
  std::unordered_set<HMODULE> hot_patched_modules_;

  pe::HotPatchingWriter writer;

  IATPatchManager iat_redir;

  AsanRuntime* asan_runtime_;
 private:
  friend struct DefaultSingletonTraits<HotPatchingAsanRuntime>;
  friend class HotPatchingAsanRuntimeTest;

  HotPatchingAsanRuntime();
  ~HotPatchingAsanRuntime();

  DISALLOW_COPY_AND_ASSIGN(HotPatchingAsanRuntime);
};

}  // namespace asan
}  // namespace agent

extern "C" {

// Exposes the hot patching Asan runtime to the unittests.
// @returns the runtime instance.
agent::asan::HotPatchingAsanRuntime* hp_asan_GetActiveHotPatchingAsanRuntime();

}

#endif  // SYZYGY_AGENT_ASAN_HOT_PATCHING_ASAN_RUNTIME_H_
