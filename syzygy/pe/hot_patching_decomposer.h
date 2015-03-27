// Copyright 2013 Google Inc. All Rights Reserved.
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
// The HotPatchingDecomposer decomposes a loaded module into an ImageLayout and
// its corresponding BlockGraph.
//
// The module must have been instrumented with the PEHotPatchingTransform
// first.

#ifndef SYZYGY_PE_IN_MEMORY_DECOMPOSER_H_
#define SYZYGY_PE_IN_MEMORY_DECOMPOSER_H_

#include <windows.h>  // NOLINT

#include "base/win/pe_image.h"  // fwd declare? base::win::PEImage
#include "syzygy/block_graph/hot_patching_metadata.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h" 

namespace pe {

class HotPatchingDecomposer {
 public:

  //TODO
  // Caller must ensure that the module does not get unloaded while decomposing
  // and while using the decomposed block graph.
  HotPatchingDecomposer(HMODULE module)
      : image_layout_(nullptr),
        image_(nullptr),
        last_code_block_id_(0U),
        module_(module) {};

  //TODO
  bool Decompose(ImageLayout* image_layout);

 protected:

  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BlockGraph::BlockType BlockType;
  typedef core::RelativeAddress RelativeAddress;

  // This function uses the hot patching block metadata to create the
  // corresponding code block in the block graph.
  BlockGraph::Block* ProcessHpCodeBlock(
      const block_graph::HotPatchingBlockMetadata& block_metadata);

  BlockGraph::Block* CreateBlock(BlockType type,
                                 RelativeAddress address,
                                 BlockGraph::Size size,
                                 const base::StringPiece& name);

  bool SectionCreateCallback(const base::win::PEImage &image,
                             PIMAGE_SECTION_HEADER header,
                             PVOID section_start,
                             DWORD section_size,
                             PVOID cookie);

 private:
  ImageLayout* image_layout_;
  BlockGraph::AddressSpace* image_;
  //TODO
  // This variable is used to generate increasing IDs for the code blocks.
  size_t last_code_block_id_;

  // The handle to the module being decomposed.
  HMODULE module_;
};

}  // namespace pe

#endif  // SYZYGY_PE_DECOMPOSER_H_ 
