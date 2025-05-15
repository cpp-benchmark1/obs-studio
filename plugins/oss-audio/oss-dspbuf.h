#ifndef OSS_DSPBUF_H
#define OSS_DSPBUF_H

struct oss_dspbuf_info {
    void *buf;
    size_t size;
    int tag;
};

void oss_dspbuf_entry(struct oss_dspbuf_info *info);

#endif 