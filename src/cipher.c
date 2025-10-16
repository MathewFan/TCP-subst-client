#include "common.h"
#include <stddef.h>

int apply_subst(const uint8_t map[256], const uint8_t *in, size_t n, uint8_t *out) {
  for (size_t i = 0; i < n; i++) out[i] = map[in[i]];
  return 0;
}
