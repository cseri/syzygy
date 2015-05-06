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
// This class redirects the functions in the import address table of imported
// modules.

#ifndef SYZYGY_AGENT_ASAN_IAT_PATCH_MANAGER_H_
#define SYZYGY_AGENT_ASAN_IAT_PATCH_MANAGER_H_

#include <windows.h>

#include "base/macros.h"

namespace agent {
namespace asan {

class IATPatchManager {
 public:
  // This structure describes an import redirect rule.
  struct IATRedirectRule {
    // The name of the module that contains the function that needs to be
    // redirected.
    const char* import_module_name;

    // The name of the function that needs to be redirected.
    const char* import_name;

    // The new function that should be called. The two functions must have
    // the same signature (return values, parameters, calling convention etc.).
    void* target_function;
  };

  IATPatchManager();
  ~IATPatchManager();

  // Redirects functions in the import address table (IAT) of the module
  // using redirect rules.
  // @param module The handle to the module that's import address table should
  //     be altered.
  // @param entries An array of IATRedirectRule structures that describe the
  //     functions that need to be redirected. This array must be terminated
  //     by an entry that has nullptr for |import_name|.
  size_t RedirectImports(HMODULE module,
                         const IATRedirectRule* entries);

 private:
  DISALLOW_COPY_AND_ASSIGN(IATPatchManager);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_IAT_PATCH_MANAGER_H_
