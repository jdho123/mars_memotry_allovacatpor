#include "allocator.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "crc32.h"

typedef uint32_t SIZE_T;
typedef uint32_t OFFSET_T;
typedef uint32_t CHECKSUM_T;

#define ALIGN (SIZE_T)40
#define GLOBAL_MAGIC (uint32_t)0xCAFEBABE
#define HEADER_MAGIC (uint32_t)0xDEADBEEF
#define INITIAL_PADDING (SIZE_T)16
#define MIN_PAYLOAD_SIZE (SIZE_T)16

#define BLOCK_FREE (uint8_t)0x01
#define BLOCK_ALLOCATED (uint8_t)0x02
#define BLOCK_QUARANTINE (uint8_t)0x04

typedef struct {
  uint32_t magic;
  SIZE_T block_size;
  uint8_t flags;
  uint32_t payload_size;  // Required as dynamic padding after payload makes
                          // this impossible to calculate from block_size
  CHECKSUM_T payload_checksum;
  CHECKSUM_T header_checksum;
} BlockHeader;

typedef struct {
  SIZE_T block_size;
  SIZE_T payload_size;
  uint8_t flags;
  CHECKSUM_T footer_checksum;
} BlockFooter;

typedef struct {
  void *start;
  SIZE_T size;
} BlockBounds;

// Static constants
static uint8_t *s_heap = NULL;
static size_t s_heap_size = 0;
static uint8_t s_unused_pattern[5];

// Finds next memory address aligned to ALIGN
SIZE_T align_up(SIZE_T x, SIZE_T align) {
  SIZE_T r = x % align;
  if (r == 0) return x;
  return x + (align - r);
}

// Finds payload ptr from BlockHeader ptr
void *get_payload_ptr(BlockHeader *block) {
  return (uint8_t *)block + sizeof(BlockHeader);
}

// Finds BlockHeader ptr from payload ptr
BlockHeader *get_block_ptr_payload(void *payload_ptr) {
  return (BlockHeader *)((uint8_t *)payload_ptr - sizeof(BlockHeader));
}

// Finds BlockFooter ptr from BlockHeader ptr
BlockFooter *get_footer_ptr(BlockHeader *block) {
  return (BlockFooter *)((uint8_t *)block + block->block_size -
                         sizeof(BlockFooter));
}

// Finds offset of a ptr within the heap
OFFSET_T calculate_offset(uint8_t *ptr) { return (OFFSET_T)(ptr - s_heap + INITIAL_PADDING); }

// Datermines whether a ptr is within the heap
bool within_heap(uint8_t *ptr) {
  return ptr >= s_heap && ptr < (s_heap + s_heap_size);
}

// Calculates the minimum size of a block
SIZE_T calculate_minimum_block_size() {
  return sizeof(BlockHeader) + MIN_PAYLOAD_SIZE + sizeof(BlockFooter);
}

// Creates a new block of a given size at the given block ptr
void create_block(void *block, SIZE_T size) {
  BlockHeader *block_header = (BlockHeader *)block;
  memset(block_header, 0, sizeof(BlockHeader));

  block_header->magic = HEADER_MAGIC;
  block_header->block_size = size;
  block_header->flags = BLOCK_FREE;
  block_header->payload_size = 0;
  block_header->payload_checksum = 0;
  size_t data_length = offsetof(BlockHeader, header_checksum);
  block_header->header_checksum =
      crc32((const void *)block_header, data_length);

  BlockFooter *footer = get_footer_ptr(block_header);
  memset(footer, 0, sizeof(BlockFooter));

  footer->block_size = size;
  footer->payload_size = 0;
  footer->flags = BLOCK_FREE;
  data_length = offsetof(BlockFooter, footer_checksum);
  footer->footer_checksum = crc32((const void *)footer, data_length);
}

// Initialize a heap with a single block
int mm_init(uint8_t *heap, size_t heap_size) {
  if (heap == NULL || heap_size < calculate_minimum_block_size()) {
    return -1;
  }

  s_heap = heap + INITIAL_PADDING;
  s_heap_size = heap_size - INITIAL_PADDING;

  memcpy(s_unused_pattern, heap, 5);  // Copy pattern for unused memory

  create_block((void *)s_heap, s_heap_size);  // Create first block

  return 0;
}

// Check that header data is valid and uncorrupted
bool validate_block_header(BlockHeader *block) {
  if (block->magic != HEADER_MAGIC) return false;

  size_t data_length = offsetof(BlockHeader, header_checksum);
  CHECKSUM_T calculated_header_checksum =
      crc32((const void *)block, data_length);
  if (calculated_header_checksum != block->header_checksum) return false;

  return true;
}

// Check that footer data is valid and uncorrupted
bool validate_block_footer(BlockFooter *footer) {
  size_t data_length = offsetof(BlockFooter, footer_checksum);
  CHECKSUM_T calculated_footer_checksum =
      crc32((const void *)footer, data_length);
  if (calculated_footer_checksum != footer->footer_checksum) return false;

  return true;
}

// Check that header and footer data agree
bool is_metadata_consistent(BlockHeader *block, BlockFooter *footer) {
  return block->block_size == footer->block_size &&
         block->flags == footer->flags &&
         block->payload_size == footer->payload_size;
}

// Checks that all of a blocks metadata is uncorrupt and consistent
bool validate_block_metadata(BlockHeader *block) {
  if (!validate_block_header(block)) return false;

  BlockFooter *footer = get_footer_ptr(block);

  if (!validate_block_footer(footer)) return false;

  return is_metadata_consistent(block, footer);
}

// Checks that payload data is uncorrupt
bool validate_block_payload(BlockHeader *block) {
  if (block->payload_checksum == 0) return true;

  CHECKSUM_T calculated_payload_checksum =
      crc32((const void *)get_payload_ptr(block), block->payload_size);
  if (calculated_payload_checksum != block->payload_checksum) return false;

  return true;
}

// Calculates the size of a fully aligned block of a given payload_size
SIZE_T calculate_aligned_block_size(SIZE_T payload_size) {
  SIZE_T aligned_size =
      sizeof(BlockHeader) + align_up(payload_size, ALIGN) + sizeof(BlockFooter);
  //SIZE_T aligned_size = align_up(unaligned_size, ALIGN);
  return aligned_size >= calculate_minimum_block_size()
             ? aligned_size
             : calculate_minimum_block_size();
}

// Divides a block into two blocks
bool split_block(BlockHeader *block, SIZE_T size) {
  BlockFooter *second_footer = get_footer_ptr(block);

  SIZE_T first_size = size;
  SIZE_T second_size = block->block_size - first_size;

  if (second_size < calculate_minimum_block_size()) return false;

  uint8_t *split_ptr = (uint8_t *)block + first_size;

  // Create second header

  BlockHeader second_header = {.magic = HEADER_MAGIC,
                               .block_size = second_size,
                               .payload_size = 0,
                               .flags = BLOCK_FREE,
                               .payload_checksum = 0,
                               .header_checksum = 0};

  size_t data_length = offsetof(BlockHeader, header_checksum);
  second_header.header_checksum =
      crc32((const void *)&second_header, data_length);

  memcpy(split_ptr, &second_header, sizeof(BlockHeader));

  // Create first footer

  BlockFooter first_footer = {
      .block_size = first_size,
      .payload_size = 0,
      .flags = BLOCK_FREE, 
      .footer_checksum = 0
    };

  data_length = offsetof(BlockFooter, footer_checksum);
  first_footer.footer_checksum =
      crc32((const void *)&first_footer, data_length);

  memcpy(split_ptr - sizeof(BlockFooter), &first_footer, sizeof(BlockFooter));

  // Update first header

  block->block_size = first_size;
  data_length = offsetof(BlockHeader, header_checksum);
  block->header_checksum = crc32((const void *)block, data_length);

  // Update second footer

  second_footer->block_size = second_size;
  second_footer->payload_size = 0;
  second_footer->flags = BLOCK_FREE;
  data_length = offsetof(BlockFooter, footer_checksum);
  second_footer->footer_checksum =
      crc32((const void *)second_footer, data_length);

  return true;
}

// Scans forward or backward for the next valid block or the heap edge
BlockHeader *scan_next_block(uint8_t *ptr, bool reverse) {
  while (within_heap(ptr)) {
    BlockHeader *block = (BlockHeader *)ptr;
    if (validate_block_metadata(block)) {
      return block;
    }
    if (reverse)
      ptr -= 1;
    else
      ptr += 1;
  }
  return NULL;
}

// Marks a block as quarantined
void quarantine_block(BlockHeader *block, SIZE_T size) {
  uint8_t *payload_ptr = get_payload_ptr(block);
  SIZE_T payload_size = size - sizeof(BlockHeader) - sizeof(BlockFooter);
  write_pattern(payload_ptr, payload_size);

  BlockFooter *footer = get_footer_ptr(block);
  footer->block_size = size;
  footer->flags = BLOCK_QUARANTINE;
  size_t data_length = offsetof(BlockFooter, footer_checksum);
  footer->footer_checksum = crc32((const void *)footer, data_length);

  block->magic = HEADER_MAGIC;
  block->block_size = size;
  block->flags = BLOCK_QUARANTINE;
  block->payload_checksum = 0;
  data_length = offsetof(BlockHeader, header_checksum);
  block->header_checksum = crc32((const void *)block, data_length);
}

// Attempts to repair a corrupted block
bool repair_block(BlockHeader *block, SIZE_T size) {
  BlockFooter *footer =
      (BlockFooter *)((uint8_t *)block + size - sizeof(BlockFooter));

  bool header_valid = validate_block_header(block);
  bool footer_valid = validate_block_footer(footer);

  if (header_valid && !footer_valid) {
    memset((void *)footer, 0, sizeof(BlockFooter));
    footer->block_size = block->block_size;
    footer->payload_size = block->payload_size;
    footer->flags = block->flags;
    size_t data_length = offsetof(BlockFooter, footer_checksum);
    footer->footer_checksum = crc32((const void *)footer, data_length);
  } else if (!header_valid && footer_valid) {
    CHECKSUM_T payload_checksum = block->payload_checksum;

    memset((void *)block, 0, sizeof(BlockHeader));
    block->magic = HEADER_MAGIC;
    block->block_size = footer->block_size;
    block->payload_size = footer->payload_size;
    block->flags = footer->flags;
    block->payload_checksum = payload_checksum;
    size_t data_length = offsetof(BlockHeader, header_checksum);
    block->header_checksum = crc32((const void *)block, data_length);

    if (!validate_block_header(block)) return false;
  } else if (!header_valid && !footer_valid) {
    return false;
  }

  return is_metadata_consistent(block, footer);
}

// Writes repeating 5 byte pattern to the given memory region
void write_pattern(uint8_t *ptr, SIZE_T size) {
  OFFSET_T start = calculate_offset(ptr);

  for (size_t i = start; i < start + size; i++) {
    ptr[i - start] = s_unused_pattern[i % 5];
  }
}

void *mm_malloc(size_t size) {
  SIZE_T aligned_size = calculate_aligned_block_size(size);

  BlockHeader *current_block = (BlockHeader *)s_heap;

  // Iterate until the next valid free block is found or return NULL
  while (within_heap((uint8_t *)current_block)) {
    if (!validate_block_metadata(current_block)) {
      BlockHeader *next_block =
          scan_next_block((uint8_t *)current_block, false);

      SIZE_T block_size;
      if (next_block == NULL) {  // Block is at the end of the heap
        block_size = s_heap_size - calculate_offset((uint8_t *)current_block);
      } else {
        block_size = (uint8_t *)next_block - (uint8_t *)current_block;
      }

      // Attempt to repair block and if not quarantine
      if (!repair_block(current_block, block_size)) {
        quarantine_block(current_block, block_size);
        current_block = next_block;
        continue;
      }
    }

    if (current_block->flags == BLOCK_FREE &&
        current_block->block_size >= aligned_size) {
      break;
    }

    current_block =
        (BlockHeader *)((uint8_t *)current_block + current_block->block_size);
  }

  if (!within_heap((uint8_t *)current_block)) return NULL;

  split_block(current_block, aligned_size);

  uint8_t *payload_ptr = get_payload_ptr(current_block);

  current_block->flags = BLOCK_ALLOCATED;
  current_block->payload_size = size;
  memset(payload_ptr, 0, current_block->payload_size);
  current_block->payload_checksum =
      crc32((const void *)get_payload_ptr(current_block),
            current_block->payload_size);
  size_t data_length = offsetof(BlockHeader, header_checksum);
  current_block->header_checksum =
      crc32((const void *)current_block, data_length);

  BlockFooter *footer = get_footer_ptr(current_block);
  footer->block_size = current_block->block_size;
  footer->payload_size = size;
  footer->flags = BLOCK_ALLOCATED;
  data_length = offsetof(BlockFooter, footer_checksum);
  footer->footer_checksum = crc32((const void *)footer, data_length);

  return payload_ptr;
}

// Given a pointer within a corrupt region, finds the bounds of this region
BlockBounds find_corrupted_bounds(uint8_t *ptr) {
  BlockHeader *next_block = scan_next_block(ptr, false);
  BlockHeader *prev_block = scan_next_block(ptr, true);

  void *block;
  if (prev_block == NULL) {
    block = (void *)s_heap;
  } else {
    block = (void *)((uint8_t *)prev_block + prev_block->block_size);
  }

  SIZE_T block_size;
  if (next_block == NULL) {
    block_size = s_heap_size - calculate_offset((uint8_t *)block);
  } else {
    block_size = (uint8_t *)next_block - (uint8_t *)block;
  }

  return (BlockBounds){block, block_size};
}

int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
  if (ptr == NULL || !within_heap((uint8_t *)ptr) || buf == NULL) return -1;

  BlockHeader *block = get_block_ptr_payload(ptr);

  if (!validate_block_metadata(block) ||
      !within_heap((uint8_t *)block + block->block_size)) {
    BlockBounds corrupted_bounds = find_corrupted_bounds((uint8_t *)block);

    if (corrupted_bounds.size == 0) return -1;

    if (!repair_block((BlockHeader *)corrupted_bounds.start,
                      corrupted_bounds.size)) {
      quarantine_block((BlockHeader *)corrupted_bounds.start,
                       corrupted_bounds.size);
      return -1;
    }
  } else if (block->flags != BLOCK_ALLOCATED || !validate_block_payload(block)) {
    quarantine_block(block, block->block_size);
    return -1;
  }

  if (offset >= block->payload_size) return 0;

  SIZE_T bytes_available = block->payload_size - offset;
  if (len > bytes_available || offset + len != block->payload_size) return -1;

  memcpy(buf, (uint8_t *)ptr + offset, len);

  return (int)len;
}

int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
  if (ptr == NULL || !within_heap((uint8_t *)ptr) || src == NULL) return -1;

  BlockHeader *block = get_block_ptr_payload(ptr);

  if (!validate_block_metadata(block) ||
      !within_heap((uint8_t *)block + block->block_size)) {
    BlockBounds corrupted_bounds = find_corrupted_bounds((uint8_t *)block);

    if (corrupted_bounds.size == 0) return -1;

    if (!repair_block((BlockHeader *)corrupted_bounds.start,
                      corrupted_bounds.size)) {
      quarantine_block((BlockHeader *)corrupted_bounds.start,
                       corrupted_bounds.size);
      return -1;
    }
  } else if (block->flags != BLOCK_ALLOCATED || !validate_block_payload(block)) {
    quarantine_block(block, block->block_size);
    return -1;
  }

  if (offset >= block->payload_size) return 0;

  SIZE_T bytes_available = block->payload_size - offset;
  if (len > bytes_available || offset + len != block->payload_size) return -1;

  memcpy((uint8_t *)ptr + offset, src, len);

  block->payload_checksum = crc32((const void *)ptr, block->payload_size);
  size_t data_length = offsetof(BlockHeader, header_checksum);
  block->header_checksum = crc32((const void *)block, data_length);

  return (int)len;
}

// Joins adjecent free blocks into a larger single free block
BlockHeader *coalesce_blocks(BlockHeader *block) {
  BlockHeader *next_block =
      (BlockHeader *)((uint8_t *)block + block->block_size);
  if (within_heap((uint8_t *)next_block) && validate_block_header(next_block) &&
      next_block->flags == BLOCK_FREE) {
    block->block_size += next_block->block_size;
    size_t data_length = offsetof(BlockHeader, header_checksum);
    block->header_checksum = crc32((const void *)block, data_length);

    BlockFooter *footer = get_footer_ptr(next_block);
    footer->block_size = block->block_size;
    footer->flags = BLOCK_FREE;
    data_length = offsetof(BlockFooter, footer_checksum);
    footer->footer_checksum = crc32((const void *)footer, data_length);
  }

  BlockFooter *prev_footer =
      (BlockFooter *)((uint8_t *)block - sizeof(BlockFooter));
  if (within_heap((uint8_t *)prev_footer) &&
      validate_block_footer(prev_footer) && prev_footer->flags == BLOCK_FREE) {
    BlockHeader *prev_block =
        (BlockHeader *)((uint8_t *)block - prev_footer->block_size);
    if (validate_block_metadata(prev_block)) {
      prev_block->block_size += block->block_size;
      size_t data_length = offsetof(BlockHeader, header_checksum);
      prev_block->header_checksum =
          crc32((const void *)prev_block, data_length);

      BlockFooter *footer = get_footer_ptr(block);
      footer->block_size = prev_block->block_size;
      data_length = offsetof(BlockFooter, footer_checksum);
      footer->footer_checksum = crc32((const void *)footer, data_length);

      block = prev_block;
    }
  }

  return block;
}

void mm_free(void *ptr) {
  if (ptr == NULL || !within_heap((uint8_t *)ptr)) return;

  BlockHeader *block = get_block_ptr_payload(ptr);

  if (!validate_block_metadata(block)) {
    BlockBounds corrupted_bounds = find_corrupted_bounds((uint8_t *)block);

    if (corrupted_bounds.size == 0) return;

    create_block(corrupted_bounds.start, corrupted_bounds.size);
  } else if (block->flags == BLOCK_FREE)
    return;

  block->flags = BLOCK_FREE;
  block->payload_size = 0;
  block->payload_checksum = 0;
  size_t data_length = offsetof(BlockHeader, header_checksum);
  block->header_checksum = crc32((const void *)block, data_length);

  BlockFooter *footer = get_footer_ptr(block);
  footer->payload_size = 0;
  footer->flags = BLOCK_FREE;
  data_length = offsetof(BlockFooter, footer_checksum);
  footer->footer_checksum = crc32((const void *)footer, data_length);

  block = coalesce_blocks(block);

  SIZE_T payload_size =
      block->block_size - sizeof(BlockHeader) - sizeof(BlockFooter);
  write_pattern((uint8_t *)block + sizeof(BlockHeader), payload_size);
}

void mm_heap_stats(void) {
  printf("Heap Statistics:\n");
  printf("  Heap Start: %p\n", (void *)s_heap - INITIAL_PADDING);
  printf("  Heap Size: %zu bytes\n", s_heap_size + INITIAL_PADDING);
  printf("  Initial Padding: %zu bytes\n", INITIAL_PADDING);
  printf("  ALIGN: %u bytes\n", ALIGN);
  printf("  BlockHeader size: %zu bytes\n", sizeof(BlockHeader));
  printf("  BlockFooter size: %zu bytes\n", sizeof(BlockFooter));
  printf("  MIN_PAYLOAD_SIZE: %u bytes\n", MIN_PAYLOAD_SIZE);
  printf("  Minimum Block Size: %u bytes\n", calculate_minimum_block_size());

  BlockHeader *current_block = (BlockHeader *)s_heap;
  int block_count = 0;
  size_t allocated_bytes = 0;
  size_t free_bytes = 0;
  size_t quarantined_bytes = 0;
  size_t corrupted_bytes = 0;

  while (within_heap((uint8_t *)current_block)) {
    block_count++;
    printf("Block %d at offset %u:\n", block_count,
           calculate_offset((uint8_t *)current_block));
    printf("  Address: %p\n", (void *)current_block);

    bool metadata_valid = validate_block_metadata(current_block);
    bool payload_valid = validate_block_payload(current_block);

    if (!metadata_valid) {
      printf("  Status: CORRUPTED (Metadata Invalid)\n");
      corrupted_bytes += current_block->block_size;
      BlockBounds corrupted_bounds =
          find_corrupted_bounds((uint8_t *)current_block);
      printf("  Corrupted Block Bounds: Start %p, Size %u\n",
             corrupted_bounds.start, corrupted_bounds.size);
      current_block = (BlockHeader *)((uint8_t *)corrupted_bounds.start +
                                      corrupted_bounds.size);
      continue;
    }

    printf("  Magic: 0x%X (Expected 0x%X)\n", current_block->magic,
           HEADER_MAGIC);
    printf("  Block Size: %u bytes\n", current_block->block_size);
    printf("  Flags: 0x%X (", current_block->flags);
    if (current_block->flags == BLOCK_FREE) {
      printf("FREE)\n");
      free_bytes += current_block->block_size;
    } else if (current_block->flags == BLOCK_ALLOCATED) {
      printf("ALLOCATED)\n");
      allocated_bytes += current_block->block_size;
    } else if (current_block->flags == BLOCK_QUARANTINE) {
      printf("QUARANTINE)\n");
      quarantined_bytes += current_block->block_size;
    } else {
      printf("UNKNOWN)\n");
    }
    printf("  Payload Checksum: 0x%X\n", current_block->payload_checksum);
    printf("  Header Checksum: 0x%X\n", current_block->header_checksum);

    BlockFooter *footer = get_footer_ptr(current_block);
    printf("  Footer Address: %p\n", (void *)footer);
    printf("  Footer Block Size: %u bytes\n", footer->block_size);
    printf("  Footer Payload Size: %u bytes\n", footer->payload_size);
    printf("  Footer Flags: 0x%X\n", footer->flags);
    printf("  Footer Checksum: 0x%X\n", footer->footer_checksum);

    if (!payload_valid) {
      printf("  Status: CORRUPTED (Payload Invalid)\n");
      corrupted_bytes += current_block->block_size;
    } else {
      printf("  Status: OK\n");
    }

    current_block =
        (BlockHeader *)((uint8_t *)current_block + current_block->block_size);
  }

  printf("Summary:\n");
  printf("  Total Blocks: %d\n", block_count);
  printf("  Total Allocated Bytes: %zu\n", allocated_bytes);
  printf("  Total Free Bytes: %zu\n", free_bytes);
  printf("  Total Quarantined Bytes: %zu\n", quarantined_bytes);
  printf("  Total Corrupted Bytes: %zu\n", corrupted_bytes);
  printf("  Total Heap Usage: %zu bytes\n",
         allocated_bytes + free_bytes + quarantined_bytes + corrupted_bytes);
  printf("  Heap Utilization: %.2f%%\n",
         (double)(allocated_bytes + quarantined_bytes) / s_heap_size * 100.0);
}
