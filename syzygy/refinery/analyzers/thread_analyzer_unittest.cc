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

#include "syzygy/refinery/analyzers/thread_analyzer.h"

#include <stdint.h>

#include "gtest/gtest.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

TEST(ThreadAnalyzerTest, Basic) {
  Minidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));
  ProcessState process_state;

  ThreadAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(minidump, &process_state));

  scoped_refptr<ProcessState::Layer<Stack>> stack_layer;
  ASSERT_TRUE(process_state.FindLayer(&stack_layer));

  ASSERT_LE(1, stack_layer->size());
  // TODO(siggi): Flesh out layer so that it can be enumerated in some way for
  //     more elaborate testing.
}

}  // namespace refinery
