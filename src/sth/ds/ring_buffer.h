#ifndef _STH_DS_RING_BUFFER_H_
#define _STH_DS_RING_BUFFER_H_

// https://www.snellman.net/blog/archive/2016-12-13-ring-buffers/

#define sth_ds_ring_buffer_mask(cap, v) ((v) & ((cap) - 1))

#define sth_ds_ring_buffer_init(rb, backing_buffer, capacity) \
    do { \
        size_t _cap_ = (capacity); \
        STH_BASE_ASSERT((_cap_ & (_cap_-1)) == 0 && "ring buffer capacity must be a power of 2"); \
        (rb)->items = STH_BASE_DECLTYPE((rb)->items) (backing_buffer); \
        (rb)->read = 0; \
        (rb)->write = 0; \
        (rb)->cap = _cap_; \
    } while (0)

#define sth_ds_ring_buffer_is_empty(rb) \
    ((rb)->read == (rb)->write)

#define sth_ds_ring_buffer_size(rb) \
    ((rb)->write - (rb)->read)

#define sth_ds_ring_buffer_is_full(rb) \
    (sth_ds_ring_buffer_size((rb)) == (rb)->cap)

#define sth_ds_ring_buffer_push(rb, item) \
    ((!sth_ds_ring_buffer_is_full((rb))) \
     ? ((rb)->write += 1, (rb)->items[sth_ds_ring_buffer_mask((rb)->cap, (rb)->write)] = (item), STH_OK) \
     : STH_FAILED)

// Get first item and advance `read` pointer
#define sth_ds_ring_buffer_advance(rb) \
    ((!sth_ds_ring_buffer_is_empty((rb))) \
     ? ((rb)->read += 1, (rb)->items[sth_ds_ring_buffer_mask((rb)->cap, (rb)->read)], STH_OK) \
     : STH_FAILED)

// Get first item, store it in `out` parameter and advance `read` pointer
#define sth_ds_ring_buffer_advance_out(rb, out) \
    ((!sth_ds_ring_buffer_is_empty((rb))) \
     ? ((rb)->read += 1, (out) = (rb)->items[sth_ds_ring_buffer_mask((rb)->cap, (rb)->read)], STH_OK) \
     : STH_FAILED)

// Get first item without advancing
#define sth_ds_ring_buffer_peek(rb) \
    ((rb)->items[sth_ds_ring_buffer_mask((rb)->cap, (rb)->read + 1)])


#ifdef STH_STRIP_PREFIX
    #define ring_buffer_mask        sth_ds_ring_buffer_mask
    #define ring_buffer_init        sth_ds_ring_buffer_init
    #define ring_buffer_is_empty    sth_ds_ring_buffer_is_empty
    #define ring_buffer_is_full     sth_ds_ring_buffer_is_full
    #define ring_buffer_size        sth_ds_ring_buffer_size
    #define ring_buffer_push        sth_ds_ring_buffer_push
    #define ring_buffer_push        sth_ds_ring_buffer_push
    #define ring_buffer_advance     sth_ds_ring_buffer_advance
    #define ring_buffer_advance_out sth_ds_ring_buffer_advance_out
    #define ring_buffer_peek        sth_ds_ring_buffer_peek
#endif // STH_STRIP_PREFIXES

#endif // _STH_DS_RING_BUFFER_H_
