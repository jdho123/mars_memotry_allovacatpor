#include "crc32.h"

#if defined(__x86_64__) || defined(_M_X64)
#include <nmmintrin.h>
#define PLATFORM_X86
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_acle.h>
#define PLATFORM_ARM
#endif

uint32_t crc32(const void *data, size_t len) {
  const uint8_t *buffer = (const uint8_t *)data;
  uint32_t crc = 0xFFFFFFFF;

// --- Intel/AMD Path ---
#if defined(PLATFORM_X86)
  size_t i = 0;
  for (; i + 4 <= len; i += 4) {
    uint32_t val = *(uint32_t *)(buffer + i);
    crc = _mm_crc32_u32(crc, val);
  }

  // Account for trailing bytes
  for (; i < len; i++) {
    crc = _mm_crc32_u8(crc, buffer[i]);
  }

// --- ARM / Apple Silicon Path
#elif defined(PLATFORM_ARM)
  size_t i = 0;
  for (; i + 4 <= len; i += 4) {
    uint32_t val = *(uint32_t *)(buffer + i);
    crc = __crc32w(crc, val);
  }

  // Account for trailing bytes
  for (; i < len; i++) {
    crc = __crc32b(crc, buffer[i]);
  }
#endif

  return crc ^ 0xFFFFFFFF;
}
