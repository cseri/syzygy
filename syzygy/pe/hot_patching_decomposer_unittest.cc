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

#include "syzygy/pe/hot_patching_decomposer.h"

#include "base/win/pe_image.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"

using block_graph::BlockGraph;

namespace pe {

namespace {

class HotPatchingDecomposerTest : public testing::PELibUnitTest {
 public:

  void foo() {
    // TODO relink first to have metadata.

    base::FilePath test_dll_path = testing::GetExeRelativePath(testing::kTestDllName);
    testing::ScopedHMODULE module;
    LoadTestDll(test_dll_path, &module);

    base::win::PEImage image(module);
    pe::ImageLayout layout(&block_graph_);
  
    HotPatchingDecomposer imd(module);
    imd.Decompose(&layout);
  }

  //
  BlockGraph block_graph_;
};

}  // namespace

TEST_F(HotPatchingDecomposerTest, Dummy) {
  foo();
}

}  // namespace pe
