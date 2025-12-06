#include "allocator.h"
#include "crc32.h"

#include <stdbool.h>
#include <string.h>


typedef uint32_t SIZE_T;
typedef uint32_t OFFSET_T;
typedef uint32_t CHECKSUM_T;

#define ALIGN (SIZE_T)40
#define HEADER_MAGIC (uint32_t)0xDEADBEEF
#define HEADER_PADDING (SIZE_T)20
#define MIN_PAYLOAD_SIZE (SIZE_T)28

#define BLOCK_FREE (uint8_t)0x01
#define BLOCK_ALLOCATED (uint8_t)0x02
#define BLOCK_QUARANTINE (uint8_t)0x04

typedef struct {
    OFFSET_T free_list_head;
    OFFSET_T quarantine_list_head;
    uint8_t unused_pattern[5];
    CHECKSUM_T checksum;
} GlobalHeader;

typedef struct {
    uint32_t magic;
    SIZE_T block_size;
    uint8_t flags;
    CHECKSUM_T payload_checksum;
    CHECKSUM_T header_checksum;
} BlockHeader;

typedef struct {
    SIZE_T block_size;
    uint8_t flags;
    CHECKSUM_T footer_checksum;
} BlockFooter;


static uint8_t* s_heap = NULL;
static size_t s_heap_size = 0;


SIZE_T align_up(SIZE_T x, SIZE_T align) {
    SIZE_T r = x % align;
    if (r == 0) return x;
    return x + (align - r);
}


BlockHeader *get_block_ptr_offset(OFFSET_T offset) {
    return (BlockHeader *)(s_heap + offset);
}


void *get_payload_ptr(BlockHeader *block) {
    return (uint8_t *)block + sizeof(BlockHeader) + HEADER_PADDING;
}


BlockHeader *get_block_ptr_payload(void *payload_ptr) {
    return (BlockHeader *)((uint8_t *)payload_ptr - HEADER_PADDING - sizeof(BlockHeader));
}


BlockFooter *get_footer_ptr(BlockHeader *block) {
    return (BlockFooter *)((uint8_t *)block + block->block_size - sizeof(BlockFooter));
}


OFFSET_T calculate_block_offset(BlockHeader *block) {
    return (OFFSET_T)(s_heap - (uint8_t *)block);
}

bool within_block(BlockHeader *block, OFFSET_T offset) {
    OFFSET_T block_offset = calculate_block_offset(block);
    if (offset < block_offset || offset >= block_offset + block->block_size) {
        return false;
    }

    return true;
}


SIZE_T calculate_minimum_heap_size() {
    SIZE_T headers_sum = sizeof(GlobalHeader) * 2 + sizeof(BlockHeader) + HEADER_PADDING;
    return headers_sum + MIN_PAYLOAD_SIZE + sizeof(BlockFooter);
}


int mm_init(uint8_t *heap, size_t heap_size) {
    if (heap == NULL || heap_size < calculate_minimum_heap_size()) {
        return -1;
    }

    s_heap = heap;
    s_heap_size = heap_size;

    uint8_t unused_pattern[5];
    memcpy(unused_pattern, heap, 5);

    // Initialize Global Header

    GlobalHeader *global_header = (GlobalHeader *)heap;
    memset(global_header, 0, sizeof(GlobalHeader));

    global_header->free_list_head = sizeof(GlobalHeader) * 2;
    global_header->quarantine_list_head = 0;
    memcpy(global_header->unused_pattern, unused_pattern, 5);
    
    size_t data_length = offsetof(GlobalHeader, checksum);
    global_header->checksum = crc32((const void *)global_header, data_length);

    // Create global header mirror

    memcpy((void *)(heap + sizeof(GlobalHeader)), (void *)global_header, sizeof(GlobalHeader));

    // Initialize the first Block Header

    BlockHeader *block_header = (BlockHeader *)(heap + sizeof(GlobalHeader) * 2);
    memset(block_header, 0, sizeof(BlockHeader));

    block_header->magic = HEADER_MAGIC;
    block_header->block_size = (SIZE_T)(heap_size - sizeof(GlobalHeader) * 2);
    block_header->flags = BLOCK_FREE; // Mark as free
    data_length = offsetof(BlockHeader, header_checksum);
    block_header->header_checksum = crc32((const void *)block_header, data_length);
    block_header->payload_checksum = 0;

    // Initialize the Block Footer
    BlockFooter *block_footer = (BlockFooter *)(heap + heap_size - sizeof(BlockFooter));
    memset(block_footer, 0, sizeof(BlockFooter));

    block_footer->block_size = block_header->block_size;
    block_footer->flags = BLOCK_FREE; // Mark as free
    data_length = offsetof(BlockFooter, footer_checksum);
    block_footer->footer_checksum = crc32((const void *)block_footer, data_length);

    return 0;
}


bool validate_block(BlockHeader *block) {
    if (block->magic != HEADER_MAGIC) return false;

    size_t data_length = offsetof(BlockHeader, header_checksum);
    CHECKSUM_T calculated_header_checksum = crc32((const void *)block, data_length);
    if (calculated_header_checksum != block->header_checksum) return false;

    if (block->payload_checksum != 0) {
        data_length = block->block_size - sizeof(BlockHeader) - sizeof(BlockFooter) - HEADER_PADDING;
        CHECKSUM_T calculated_payload_checksum = crc32((const void *)get_payload_ptr(block), data_length);
        if (calculated_payload_checksum != block->payload_checksum) return false;
    }

    BlockFooter *footer = get_footer_ptr(block);
    data_length = offsetof(BlockFooter, footer_checksum);
    CHECKSUM_T calculated_footer_checksum = crc32((const void *)footer, data_length);
    if (calculated_footer_checksum != footer->footer_checksum) return false;

    if (block->block_size != footer->block_size || block->flags != footer->flags) return false;

    return true;
}
