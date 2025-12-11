#include <stddef.h>
#include <stdint.h>

// Calculates the CRC32 checksum of a given memory region, using CPU intrinsics
// for efficiency
uint32_t crc32(const void *data, size_t len);
