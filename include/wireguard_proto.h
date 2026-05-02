#include <stdint.h>

typedef struct {
    uint8_t type;
    uint8_t reserved[3];
    uint8_t sender[4];
    uint8_t receiver[4];
    uint8_t counter[8];
    uint8_t auth_tag[16];
} wg_header_t;
