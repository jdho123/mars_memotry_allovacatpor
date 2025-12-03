#include "allocator.h"
#include "crc32.h"

#include <string.h>


typedef uint32_t SIZE_T;
typedef uint32_t OFFSET_T;
typedef uint32_t CHECKSUM_T;

#define ALIGN (SIZE_T)40
#define GLOBAL_HEADER_MAGIC (uint32_t)0xDEADBEEF
#define BLOCK_HEADER_MAGIC (uint32_t)0xBEEFCAFE
#define MIN_PAYLOAD_SIZE (SIZE_T)64

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
    SIZE_T block_size;
    uint8_t flags;
    OFFSET_T prev_free_offset;
    OFFSET_T next_free_offset;
    CHECKSUM_T header_checksum;
    CHECKSUM_T payload_checksum;
} BlockHeader;

typedef struct {
    OFFSET_T block_offset;
    SIZE_T old_val;
    uint8_t valid;
    CHECKSUM_T entry_checksum;
} JournalEntry;

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


SIZE_T calculate_minimum_heap_size() {
    SIZE_T headers_sum = sizeof(GlobalHeader) + sizeof(BlockHeader) + sizeof(JournalEntry);
    SIZE_T min_payload_start = align_up(headers_sum, ALIGN);
    return min_payload_start + MIN_PAYLOAD_SIZE + sizeof(BlockFooter);
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

    block_header->block_size = (SIZE_T)(heap_size - sizeof(GlobalHeader) * 2);
    block_header->flags = BLOCK_FREE; // Mark as free
    block_header->prev_free_offset = 0;
    block_header->next_free_offset = 0;
    data_length = offsetof(BlockHeader, header_checksum);
    block_header->header_checksum = crc32((const void *)block_header, data_length);
    block_header->payload_checksum = 0;

    // Initialize the first Block Journal Entry

    JournalEntry *journal_entry = (JournalEntry *)((uint8_t *)block_header + sizeof(BlockHeader));
    memset(journal_entry, 0, sizeof(JournalEntry));

    // Initialize the Block Footer
    BlockFooter *block_footer = (BlockFooter *)(heap + heap_size - sizeof(BlockFooter));
    memset(block_footer, 0, sizeof(BlockFooter));

    block_footer->block_size = block_header->block_size;
    block_footer->flags = BLOCK_FREE; // Mark as free
    data_length = offsetof(BlockFooter, footer_checksum);
    block_footer->footer_checksum = crc32((const void *)block_footer, data_length);

    return 0;
}
