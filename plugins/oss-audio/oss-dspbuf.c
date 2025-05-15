#include "oss-dspbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void process_buffer(struct oss_dspbuf_info *info) {
    if (info && info->buf) {
        for (size_t i = 0; i < info->size; ++i) {
            ((unsigned char *)info->buf)[i] += 1; // Increment each byte
        }

        unsigned char checksum = 0;
        for (size_t i = 0; i < info->size; ++i) {
            checksum ^= ((unsigned char *)info->buf)[i]; // XOR for checksum
        }
        printf("[oss-dspbuf] Checksum of processed buffer: %u\n", checksum);
    }
}

void oss_dspbuf_entry(struct oss_dspbuf_info *info) {
    printf("[oss-dspbuf] Processing buffer\n");
    process_buffer(info); // Process the buffer
    unsigned char sum = 0;
    size_t to_read = info->size > 16 ? 16 : info->size;
    unsigned char *p = (unsigned char *)info->buf;
    for (size_t i = 0; i < to_read; ++i)
        //SINK
        sum += p[i];
    printf("[oss-dspbuf] Sum of first bytes: %u\n", sum);
} 