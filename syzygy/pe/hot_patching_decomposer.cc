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

#include "syzygy/pe/hot_patching_decomposer.h"

#include "base/win/pe_image.h"
//#include "syzygy/pe/pe_utils.h"
#include "syzygy/common/defs.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockInfo;
using core::AbsoluteAddress;
using core::FileOffsetAddress;
using core::RelativeAddress;

typedef BlockGraph::Block Block;

}  // namespace

Block *HotPatchingDecomposer::ProcessHpCodeBlock(
    const block_graph::HotPatchingBlockMetadata& block_metadata) {

  // The relative address will point to the correct field as it should be
  // relocated.
  RelativeAddress data_address(block_metadata.relative_address);
  size_t data_size = block_metadata.data_size;

  // Generate a unique name for the block.
  ++last_code_block_id_;
  std::string block_name = "CodeBlock" + std::to_string(last_code_block_id_);

  // Add the block to the block graph.
  Block* block = CreateBlock(BlockGraph::CODE_BLOCK,
                             data_address,
                             data_size,
                             block_name);
  if (block == NULL) {
    LOG(ERROR) << "Unable to add code block at "
               << data_address << " with size " << data_size << ".";
    return NULL;
  }

  block->SetData(reinterpret_cast<const uint8*>(data_address.value()),
                 data_size);

  return block;
}

//TODO copied from Decomposer::CreateBlock
Block* HotPatchingDecomposer::CreateBlock(BlockType type,
                                       RelativeAddress address,
                                       BlockGraph::Size size,
                                       const base::StringPiece& name) {
  /*Block* block = image_->AddBlock(type, address, size, name);
  if (block == NULL) {
    LOG(ERROR) << "Unable to add block \"" << name.as_string() << "\" at "
               << address << " with size " << size << ".";
    return NULL;
  }

  // Mark the source range from whence this block originates. This is assuming
  // an untransformed image. To handle transformed images we'd have to use the
  // OMAP information to do this properly.
  bool pushed = block->source_ranges().Push(
      Block::DataRange(0, size),
      Block::SourceRange(address, size));
  DCHECK(pushed);

  BlockGraph::SectionId section = image_file_.GetSectionIndex(address, size);
  if (section == BlockGraph::kInvalidSectionId) {
    LOG(ERROR) << "Block \"" << name.as_string() << "\" at " << address
               << " with size " << size << " lies outside of all sections.";
    return NULL;
  }
  block->set_section(section);

  const uint8* data = image_file_.GetImageData(address, size);
  if (data != NULL)
    block->SetData(data, size);

  return block;*/
  return nullptr;
}


/*bool HotPatchingDecomposer::SectionCreateCallback(const base::win::PEImage &image,
                                               PIMAGE_SECTION_HEADER header,
                                               PVOID section_start,
                                               DWORD section_size,
                                               PVOID cookie)
{


  return true;
}*/

namespace {
//TODO this is from pe_utils_impl.h
bool CopySectionInfoToBlockGraph(const base::win::PEImage& image_file,
                                 block_graph::BlockGraph* block_graph) {
  // Iterate through the image sections, and create sections in the BlockGraph.
  size_t num_sections = image_file.GetNTHeaders()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file.GetSectionHeader(i);
    std::string name = "foo"; //TODO
    block_graph::BlockGraph::Section* section = block_graph->AddSection(
        name, header->Characteristics);
    DCHECK(section != NULL);

    // For now, we expect them to have been created with the same IDs as those
    // in the original image.
    if (section->id() != i) {
      LOG(ERROR) << "Unexpected section ID.";
      return false;
    }
  }

  return true;
}
}  // namespace

bool HotPatchingDecomposer::Decompose(ImageLayout* image_layout) {
  DCHECK_NE(static_cast<ImageLayout*>(NULL), image_layout);

  // The temporaries should be NULL.
  DCHECK_EQ(static_cast<ImageLayout*>(NULL), image_layout_);
  DCHECK_EQ(static_cast<BlockGraph::AddressSpace*>(NULL), image_);

  // Set the image format.
  image_layout->blocks.graph()->set_image_format(BlockGraph::IN_MEMORY_IMAGE);

  image_layout_ = image_layout;
  image_ = &(image_layout->blocks);

  // Initialize in-memory PE access helper.
  base::win::PEImage pe_image_(module_);

  // TODO create sections.
  /*pe_image_.EnumSections(
      base::Bind(&HotPatchingDecomposer, base::Unretained(this)), nullptr);*/
  CopySectionHeadersToImageLayout(      
      pe_image_.GetNTHeaders()->FileHeader.NumberOfSections,
      pe_image_.GetSectionHeader(0),
      &(image_layout_->sections));

  // Create the sections in the underlying block-graph.
  if (!CopySectionInfoToBlockGraph(pe_image_, image_->graph()))
    return false;



  /***********************************/
  /*       access metadata           */
  /***********************************/

  PIMAGE_SECTION_HEADER hp_sect_hdr = pe_image_.GetImageSectionHeaderByName(
      common::kHotPatchingMetadataSectionName);
  DCHECK(hp_sect_hdr != NULL);

  // Check section header.
  block_graph::HotPatchingMetadataHeader* hp_metadata_header =
      static_cast<block_graph::HotPatchingMetadataHeader*>(
          pe_image_.RVAToAddr(hp_sect_hdr->VirtualAddress));
  DCHECK(hp_metadata_header != NULL);
  if (block_graph::kHotPatchingMetadataVersion !=
      hp_metadata_header->version) {
    return false;
  }

  // Locate the block metadata array.
  // The (hp_metadata_header + 1) expression is a pointer pointing to the
  // location after the header.
  block_graph::HotPatchingBlockMetadata* hp_block_metadata_arr =
      reinterpret_cast<block_graph::HotPatchingBlockMetadata*>(
          hp_metadata_header + 1);

  // TODO create code blocks and labels.
  for (size_t i = 0; i < hp_metadata_header->number_of_blocks; ++i) {
    ProcessHpCodeBlock(hp_block_metadata_arr[i]);
  }

  /***********************************/
  /*   create filler data(?) blocks  */
  /***********************************/
  // TODO ??? 

  // TODO create references

  // TODO 
  return false;
}

};
