# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

{
  'variables': {
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'refinery',
      'type': 'none',
      'dependencies': [
        'analyzers/analyzers.gyp:*',
        'process_state/process_state.gyp:*',
        'minidump/minidump.gyp:*',
      ],
    },
    {
      'target_name': 'refinery_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'refinery_unittests',
      'type': 'executable',
      'sources': [
        'analyzers/memory_analyzer_unittest.cc',
        'analyzers/thread_analyzer_unittest.cc',
        'process_state/process_state_unittest.cc',
        'minidump/minidump_unittest.cc',
        '<(src)/base/test/run_all_unittests.cc',
      ],
      'dependencies': [
        'analyzers/analyzers.gyp:analyzers_lib',
        'minidump/minidump.gyp:minidump_lib',
        'process_state/process_state.gyp:process_state_lib',
        'refinery_unittest_utils',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/testing/gtest.gyp:gtest',
       ],
    },
  ]
}
