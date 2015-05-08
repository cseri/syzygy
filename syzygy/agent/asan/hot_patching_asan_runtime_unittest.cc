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

#include "syzygy/agent/asan/hot_patching_asan_runtime.h"

#include "gtest/gtest.h"

#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/instrument/transforms/asan_transform.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/unittest_util.h"

namespace agent {
namespace asan {

// This helper class creates a hot patching Asan instrumented test_dll.dll.
class HotPatchingAsanRelinkHelper : public testing::PELibUnitTest {
 public:
  HotPatchingAsanRelinkHelper()
      : relinker_(&policy_),
        test_dll_path_(testing::GetExeRelativePath(testing::kTestDllName)) {
    transform_.set_hot_patching(true);
  }

  void SetUp() override {
    this->CreateTemporaryDir(&temp_dir_);
    hp_test_dll_path_ = temp_dir_.Append(testing::kTestDllName);
  }

  // This is a workaround so that we can use this class in the unittest
  // fixture below that inherits from a different base class.
  void TestBody() override {
  }

  // Relinks test_dll.dll using hot patching Asan transform.
  void InstrumentAndLoadTestDll() {
    // Set up relinker.
    relinker_.set_input_path(test_dll_path_);
    relinker_.set_output_path(hp_test_dll_path_);
    relinker_.set_allow_overwrite(true);
    ASSERT_TRUE(relinker_.Init());

    relinker_.AppendTransform(&transform_);

    // Perform the actual relink.
    ASSERT_TRUE(relinker_.Relink());

    // Validate that the binary still loads.
    ASSERT_NO_FATAL_FAILURE(CheckTestDll(hp_test_dll_path_));
  }

  pe::PETransformPolicy policy_;
  pe::PERelinker relinker_;

  // Path of the original test_dll.dll.
  base::FilePath test_dll_path_;
  // Path of the temporary directory where the hot patchable DLL will be saved.
  base::FilePath temp_dir_;
  // Path of the hot patchable test_dll.dll.
  base::FilePath hp_test_dll_path_;

  // The transform used to make test_dll.dll hot patchable.
  instrument::transforms::AsanTransform transform_;
};

// Function pointer type for hp_asan_GetActiveHotPatchingRuntime.
typedef agent::asan::HotPatchingAsanRuntime*
    (__stdcall* GetActiveHotPatchingRuntimeFunctionPtr)();

class HotPatchingAsanRuntimeTest : public testing::TestWithAsanLogger {
 public:
  HotPatchingAsanRuntimeTest() : asan_hp_rtl_(nullptr),
                                 runtime_(nullptr) {
  }

  void SetUp() override {
    testing::TestWithAsanLogger::SetUp();

    // Load the Asan runtime library.
    base::FilePath asan_hp_rtl_path =
        testing::GetExeRelativePath(L"syzyasan_hp.dll");
    asan_hp_rtl_ = ::LoadLibrary(asan_hp_rtl_path.value().c_str());
    ASSERT_NE(nullptr, asan_hp_rtl_);

    // Load the function that exposes the hot patching Asan runtime.
    GetActiveHotPatchingRuntimeFunctionPtr runtime_getter =
        reinterpret_cast<GetActiveHotPatchingRuntimeFunctionPtr>(
            ::GetProcAddress(asan_hp_rtl_,
                             "hp_asan_GetActiveHotPatchingAsanRuntime"));
    ASSERT_NE(nullptr, runtime_getter);

    // Get the hot patching Asan runtime.
    runtime_ = runtime_getter();
    ASSERT_NE(static_cast<agent::asan::HotPatchingAsanRuntime*>(nullptr),
              runtime_);
  }

  void TearDown() override {
    if (asan_hp_rtl_ != nullptr) {
      ::FreeLibrary(asan_hp_rtl_);
      asan_hp_rtl_ = nullptr;
    }

    testing::TestWithAsanLogger::TearDown();
  }

 protected:
  // The hot patching Asan runtime module to test.
  HMODULE asan_hp_rtl_;

  // The hot patching Asan runtime.
  agent::asan::HotPatchingAsanRuntime* runtime_;
};

TEST_F(HotPatchingAsanRuntimeTest, TestRuntime) {
  HotPatchingAsanRelinkHelper relink_helper;
  relink_helper.SetUp();
  relink_helper.InstrumentAndLoadTestDll();

  // Load hot patched library into memory. This should construct a runtime
  // that we can query.
  testing::ScopedHMODULE module;
  relink_helper.LoadTestDll(relink_helper.hp_test_dll_path_, &module);

  // The hot patching Asan runtime must have been activated by loading the
  // instrumented dll.
  ASSERT_EQ(1U, runtime_->hot_patched_modules().count(module));

  // The module is already hot patched, this is a no-op.
  // NOTE: Calling the |HotPatch| function like this is extremely dangerous
  //     because it uses the code from the unittest executable and global
  //     variables will have two instances and the incorrect one will be used!
  ASSERT_TRUE(runtime_->HotPatch(module));

  // The test module should remain in set of hot patched modules.
  ASSERT_EQ(1U, runtime_->hot_patched_modules().count(module));
}

}  // namespace asan
}  // namespace agent
