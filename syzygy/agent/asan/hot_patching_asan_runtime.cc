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

#include "base/command_line.h"
#include "base/environment.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

// new includes
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/agent/common/hot_patcher.h"
#include "syzygy/instrument/transforms/asan_transform.h"
#include "syzygy/pe/hot_patching_decomposer.h"
#include "syzygy/pe/hot_patching_writer.h"
#include "syzygy/pe/pe_transform_policy.h"
#include <unordered_map>
#include "syzygy/agent/asan/heap_checker.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/asan_runtime_util.h"

namespace agent {
namespace asan {

namespace {

using instrument::transforms::AsanBasicBlockTransform;
using block_graph::BlockGraph;

// TODO(cseri): Calculate the size of the pool before writing the memory.
//     Currently we use a fix buffer to write into. A buffer of 50 megabytes is
//     enough for hot patching Chrome.
const size_t kHotPatchingWriterMemorySize = 50U * 1024U * 1024U;

// TODO This is copy-paste from AsanTransform!
// refactor after hot patching AsanTransform landed!
std::string GetAsanCheckAccessFunctionName(
    AsanBasicBlockTransform::MemoryAccessInfo info) {
  DCHECK(info.mode != AsanBasicBlockTransform::kNoAccess);
  DCHECK_NE(0U, info.size);
  DCHECK(info.mode == AsanBasicBlockTransform::kReadAccess ||
         info.mode == AsanBasicBlockTransform::kWriteAccess ||
         info.opcode != 0);

  const char* rep_str = NULL;
  if (info.mode == AsanBasicBlockTransform::kRepzAccess)
    rep_str = "_repz";
  else if (info.mode == AsanBasicBlockTransform::kRepnzAccess)
    rep_str = "_repnz";
  else
    rep_str = "";

  const char* access_mode_str = NULL;
  if (info.mode == AsanBasicBlockTransform::kReadAccess)
    access_mode_str = "read";
  else if (info.mode == AsanBasicBlockTransform::kWriteAccess)
    access_mode_str = "write";
  else
    access_mode_str = reinterpret_cast<char*>(GET_MNEMONIC_NAME(info.opcode));

  // For COFF images we use the decorated function name, which contains a
  // leading underscore.
  std::string function_name =
      base::StringPrintf("asan_check%s_%d_byte_%s_access%s",
                         rep_str,
                         info.size,
                         access_mode_str,
                         info.save_flags ? "" : "_no_flags");
  base::StringToLowerASCII(&function_name);
  return function_name;
}

// The linker satisfies this symbol. This gets us a pointer to our own module
// when we're loaded.
extern "C" IMAGE_DOS_HEADER __ImageBase;

void LoadHooks(bool use_liveness_analysis,
               AsanBasicBlockTransform::AsanHookMap* hooks,
               BlockGraph* block_graph) {
  typedef std::vector<AsanBasicBlockTransform::AsanHookMapEntryKey>
    AccessHookParamVector;
  typedef AsanBasicBlockTransform::MemoryAccessInfo MemoryAccessInfo;

  // TODO This is copy-paste from AsanTransform!
  // refactor to an EnumerateAccessHooks function after hot patching
  // AsanTransform landed!

  AccessHookParamVector access_hook_param_vec;

  // Import the hooks for the read/write accesses.
  for (int access_size = 1; access_size <= 32; access_size *= 2) {
    MemoryAccessInfo read_info =
        { AsanBasicBlockTransform::kReadAccess, access_size, 0, true };
    access_hook_param_vec.push_back(read_info);
    if (use_liveness_analysis) {
      read_info.save_flags = false;
      access_hook_param_vec.push_back(read_info);
    }

    MemoryAccessInfo write_info =
        { AsanBasicBlockTransform::kWriteAccess, access_size, 0, true };
    access_hook_param_vec.push_back(write_info);
    if (use_liveness_analysis) {
      write_info.save_flags = false;
      access_hook_param_vec.push_back(write_info);
    }
  }

  // Import the hooks for the read/write 10-bytes accesses.
  MemoryAccessInfo read_info_10 =
      { AsanBasicBlockTransform::kReadAccess, 10, 0, true };
  access_hook_param_vec.push_back(read_info_10);
  if (use_liveness_analysis) {
    read_info_10.save_flags = false;
    access_hook_param_vec.push_back(read_info_10);
  }

  MemoryAccessInfo write_info_10 =
      { AsanBasicBlockTransform::kWriteAccess, 10, 0, true };
  access_hook_param_vec.push_back(write_info_10);
  if (use_liveness_analysis) {
    write_info_10.save_flags = false;
    access_hook_param_vec.push_back(write_info_10);
  }

  // Import the hooks for strings/prefix memory accesses.
  const _InstructionType strings[] = { I_CMPS, I_MOVS, I_STOS };
  int strings_length = sizeof(strings)/sizeof(_InstructionType);

  for (int access_size = 1; access_size <= 4; access_size *= 2) {
    for (int inst = 0; inst < strings_length; ++inst) {
      MemoryAccessInfo repz_inst_info = {
         AsanBasicBlockTransform::kRepzAccess,
         access_size,
         strings[inst],
         true
      };
      access_hook_param_vec.push_back(repz_inst_info);

      MemoryAccessInfo inst_info = {
          AsanBasicBlockTransform::kInstrAccess,
          access_size,
          strings[inst],
          true
      };
      access_hook_param_vec.push_back(inst_info);
    }
  }

  /////// End of copy-paste form AsanTransform ////////////////////////////////

  for (const MemoryAccessInfo& entry : access_hook_param_vec) {
    std::string hook_name = GetAsanCheckAccessFunctionName(entry);

    // Find the hook in the current module.
    // TODO look the real address in the IAT!
    FARPROC hook_proc = GetProcAddress(
        reinterpret_cast<HMODULE>(&__ImageBase), hook_name.c_str());

    // Create dummy block for the hook.
    BlockGraph::Block* hook_block =
        block_graph->AddBlock(BlockGraph::CODE_BLOCK, 1U, hook_name);
    DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), hook_block);
    const uint8* image_base = reinterpret_cast<const uint8*>(&__ImageBase);
    const uint8* hook_address = reinterpret_cast<const uint8*>(hook_proc);
    hook_block->set_addr(core::RelativeAddress(hook_address - image_base));
    hook_block->SetData(hook_address, 1U);
    
    hooks->insert(std::make_pair(entry,
        BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF,
                              4U, hook_block, 0, 0)));
  }

}

}  // namespace 


HotPatchingAsanRuntime::HotPatchingAsanRuntime() : asan_runtime_(nullptr) { }

HotPatchingAsanRuntime::~HotPatchingAsanRuntime() {
  if (asan_runtime_ != nullptr) {
    TearDownAsanRuntime(&asan_runtime_);
  }
}

bool HotPatchingAsanRuntime::HotPatch(HINSTANCE instance) {
  using block_graph::BlockGraph;
  using instrument::transforms::AsanBasicBlockTransform;

  // TODO(cseri): This needs a lock. Currently we are fine because hot patching
  // happens during the loader lock.
  if (asan_runtime_ == nullptr) {
    SetUpAsanRuntime(&asan_runtime_);
    //asan_runtime_->params().check_heap_on_failure = false;
  }

  // We also initialize the writer.
  // TODO(cseri): This needs a lock. Currently we are fine because hot patching
  // happens during the loader lock.
  if (writer.virtual_memory_size() == 0U) {
    if (!writer.Init(kHotPatchingWriterMemorySize)) {
      logger_->Write("HPSyzyAsan: Failed to initialize writer.");
      return false;
    }
  }

  logger_->Write("HPSyzyAsan: Started hot patching. Module: " +
      std::to_string(reinterpret_cast<int>(instance)) +
    " PID: " + std::to_string(GetCurrentProcessId()) +
    " ThreadID: " + std::to_string(GetCurrentThreadId()));

  // Do not hot patch the same module twice in a process. 
  if (hot_patched_modules_.count(instance)) {
    logger_->Write("HPSyzyAsan: Already tried to hot patch, exiting.");
    return true;
  }
  hot_patched_modules_.insert(instance);

  size_t iat_redirect_count = iat_redir.RedirectImports(
      instance,
      kHotPatchingAsanIATRedirects);
  logger_->Write("HPSyzyAsan: Number of IAT redirects: " +
                 std::to_string(iat_redirect_count));


  Sleep(10000);
  logger_->Write("HPSyzyAsan: Waiting over.");
  uint32 start_ticks = GetTickCount();

  pe::HotPatchingDecomposer decomposer(instance);
  BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  if (!decomposer.Decompose(&image_layout)) {
    logger_->Write("HPSyzyAsan: Failed to decompose module.");
    return false;
  }

  logger_->Write("HPSyzyAsan: Decompose successful, number of blocks: " +
    std::to_string(block_graph.blocks().size()));

  // The map containing the blocks changes, so save blocks to transform first.
  std::vector<BlockGraph::Block*> blocks_to_transform;
  for (auto& entry : block_graph.blocks_mutable()) {
    // This is a hack.
    // TODO introduce a flag.
    if (entry.second.type() == BlockGraph::CODE_BLOCK && entry.second.name()[0] == 'C') {
      blocks_to_transform.push_back(&entry.second);
    }
  }

  logger_->Write("HPSyzyAsan: Number of blocks to transform: " +
    std::to_string(blocks_to_transform.size()));

  // TODO this should be member(?).
  agent::common::HotPatcher hot_patcher;

  //TODO create hookmap
  AsanBasicBlockTransform::AsanHookMap hooks;
  LoadHooks(true, &hooks, &block_graph);
  pe::PETransformPolicy pe_policy;

  int i = 0;
  int unsafe = 0;
  int hot_patched_block_count = 0;
  for (BlockGraph::Block* block : blocks_to_transform) {
    if (i % 1000 == 0) {
      logger_->Write("HPSyzyAsan: hehe: " + std::to_string(i));
    }
    ++i;
/*#if !defined(NDEBUG) 
    if (i % 100 != 0 && block->labels().size() == 1) {
      continue;
    }
#endif*/
    if (block->addr() == core::RelativeAddress(0x7c6c)) {
      DebugBreak();
    }

    FARPROC old_entry_point = reinterpret_cast<FARPROC>(block->data());

    if (!pe_policy.BlockIsSafeToBasicBlockDecompose(block)) {
      ++unsafe;
      continue;
    }

    // Apply the Asan basic block transform.
    // TODO(cseri): Read parameters from the SyzyAsan runtime.
    std::vector<BlockGraph::Block*> new_blocks;
    AsanBasicBlockTransform transform(&hooks);
    //transform.set_use_liveness_analysis(true);
    if (!ApplyBasicBlockSubGraphTransform(
        &transform, &pe_policy, &block_graph, block, &new_blocks)) {
      logger_->Write("HPSyzyAsan: Hot patching failed.");
      return false;
    }

    if (new_blocks.size() != 1U) {
      logger_->Write("HPSyzyAsan: Hot patching generated no new blocks.");
      return false;
    }
    BlockGraph::Block* transformed_block = new_blocks.front();

    // These are for easier debug only.
    transformed_block->set_alignment(32);
    transformed_block->set_padding_before(16);

    pe::HotPatchingWriter::FunctionPointer new_entry_point =
        writer.Write(transformed_block);
    if (nullptr == new_entry_point) {
      logger_->Write("HPSyzyAsan: Failed to write function to new memory.");
      return false;
    }

    if (!hot_patcher.Patch(old_entry_point, new_entry_point)) {
      logger_->Write("HPSyzyAsan: Failed to patch function.");
      return false;
    }
    //LOG(INFO) << &hot_patcher << old_entry_point << new_entry_point;
    ++hot_patched_block_count;
  }

  uint32 end_ticks = GetTickCount();
  logger_->Write("HPSyzyAsan: Hot patching completed successfully.");
  logger_->Write("HPSyzyAsan: Hot patched blocks: " +
                 std::to_string(hot_patched_block_count));
  logger_->Write("HPSyzyAsan: Skipped blocks: " + std::to_string(unsafe));
  logger_->Write("HPSyzyAsan: Time needed: " +
                 std::to_string(end_ticks - start_ticks) + " milliseconds");
  logger_->Write("HPSyzyAsan: Hot patched image size: " +
                 std::to_string(writer.GetUsedMemory()));
  return true;
}

void HotPatchingAsanRuntime::ProcessAttach(HINSTANCE instance) {
  // TODO(cseri): This is the point where it can be decided if we want to do
  //     the hot patching.
  HotPatch(instance);
}

void HotPatchingAsanRuntime::ProcessDetach(HINSTANCE instance) {
  logger_->Write("HPSyzyAsan: Detaching. Module: " +
      std::to_string(reinterpret_cast<int>(instance)) +
    " PID: " + std::to_string(GetCurrentProcessId()) +
    " ThreadID: " + std::to_string(GetCurrentThreadId()));

  auto it = hot_patched_modules_.find(instance);
  if (it != hot_patched_modules_.end()) {
    hot_patched_modules_.erase(it);
  }
}

void HotPatchingAsanRuntime::SetUp() {
  SetUpLogger();

  logger_->Write("HPSyzyAsan: Runtime loaded.");
}

void HotPatchingAsanRuntime::SetUpLogger() {
  // Setup variables we're going to use.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  scoped_ptr<AsanLogger> client(new AsanLogger);
  CHECK(env.get() != NULL);
  CHECK(client.get() != NULL);

  // Initialize the client.
  client->set_instance_id(
      base::UTF8ToWide(trace::client::GetInstanceIdForThisModule()));
  client->Init();

  // Register the client singleton instance.
  logger_.reset(client.release());
}

void WINAPI HotPatchingAsanRuntime::DllMainEntryHook(
    agent::EntryFrame* entry_frame,
    FuncAddr function) {
  HINSTANCE instance = reinterpret_cast<HINSTANCE>(entry_frame->args[0]);
  DWORD reason = entry_frame->args[1];

  switch (reason) {
    case DLL_PROCESS_ATTACH: {
      HotPatchingAsanRuntime::GetInstance()->ProcessAttach(instance);
      break;
    }

    case DLL_THREAD_ATTACH:
      // Nothing to do here.
      break;

    case DLL_THREAD_DETACH:
      // Nothing to do here.
      break;

    case DLL_PROCESS_DETACH: {
      HotPatchingAsanRuntime::GetInstance()->ProcessDetach(instance);
      break;
    }

    default:
      NOTREACHED();
      break;
  }
}

}  // namespace asan
}  // namespace agent

extern "C" {

agent::asan::HotPatchingAsanRuntime* hp_asan_GetActiveHotPatchingAsanRuntime() {
  return agent::asan::HotPatchingAsanRuntime::GetInstance();
}

}
