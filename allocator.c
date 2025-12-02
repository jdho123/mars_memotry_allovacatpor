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

struct GlobalHeader {
    uint32_t magic;
    SIZE_T heap_size;
    OFFSET_T free_list_head;
    OFFSET_T quarantine_list_head;
    uint8_t unused_pattern[5];
    CHECKSUM_T checksum;
};

struct BlockHeader {
    uint32_t magic;
    SIZE_T block_size;
    uint8_t flags;
    OFFSET_T prev_free_offset;
    OFFSET_T next_free_offset;
    CHECKSUM_T header_checksum;
};

struct JournalEntry {
    OFFSET_T block_offset;
    SIZE_T old_payload_size;
    SIZE_T new_payload_size;
    uint8_t valid;
    CHECKSUM_T entry_checksum;
};

struct BlockFooter {
    SIZE_T block_size;
    uint8_t flags;
    CHECKSUM_T footer_checksum;
};
