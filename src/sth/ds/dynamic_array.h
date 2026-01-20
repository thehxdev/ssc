#ifndef _STH_DS_DYNAMIC_ARRAY_H_
#define _STH_DS_DYNAMIC_ARRAY_H_

#define STH_DS_DA_INITIAL_CAP (256)

#define sth_ds_da_init(da, _cap) \
    do { \
        (da)->len = 0; \
        (da)->cap = ((_cap) <= 0) ? STH_DS_DA_INITIAL_CAP : (_cap); \
        (da)->items = STH_BASE_MALLOC(((da)->cap) * sizeof(*(da)->items)); \
        STH_BASE_ASSERT((da)->items); \
    } while (0)

#define sth_ds_da_reserve(da, expected_cap) \
    do { \
        if ((expected_cap) > (da)->cap) { \
            if ((da)->cap == 0) { \
                (da)->cap = STH_DS_DA_INITIAL_CAP; \
            } \
            while ((da)->cap < (expected_cap)) { \
                (da)->cap <<= 1; \
            } \
            (da)->items = STH_BASE_DECLTYPE((da)->items) STH_BASE_REALLOC((da)->items, (da)->cap * sizeof(*(da)->items)); \
            STH_BASE_ASSERT((da)->items); \
        } \
    } while (0)

#define sth_ds_da_append(da, item) \
    do { \
        sth_ds_da_reserve((da), (da)->len + 1); \
        (da)->items[(da)->len] = (item); \
        (da)->len++; \
    } while (0)

#define sth_ds_da_append_many(da, new_items, new_items_count) \
    do { \
        sth_ds_da_reserve((da), (da)->len + (new_items_count)); \
        memcpy(&(da)->items[(da)->len], (new_items), (new_items_count) * sizeof(*(da)->items)); \
        (da)->len += (new_items_count); \
    } while (0)

#define sth_ds_da_resize(da, new_size) \
    do { \
        size_t _new_size_ = (new_size); \
        sth_ds_da_reserve((da), (_new_size_)); \
        (da)->len = (_new_size_); \
    } while (0)

#define sth_ds_da_last(da) (da)->items[(STH_BASE_ASSERT((da)->len > 0), (da)->len-1)]

#define sth_ds_da_del(da, i) \
    do { \
        size_t _idx_ = (i); \
        STH_BASE_ASSERT(_idx_ < (da)->len); \
        (da)->items[_idx_] = (da)->items[(da)->len]; \
        (da)->len -= 1; \
    } while(0)

#define sth_ds_da_free(da) STH_BASE_FREE((da)->items)

#ifdef STH_STRIP_PREFIXES
    #define da_init         sth_ds_da_init
    #define da_reserve      sth_ds_da_reserve
    #define da_append       sth_ds_da_append
    #define da_append_many  sth_ds_da_append_many
    #define da_resize       sth_ds_da_resize
    #define da_last         sth_ds_da_last
    #define da_del          sth_ds_da_del
    #define da_free         sth_ds_da_free
#endif // STH_STRIP_PREFIXES

#endif // _STH_DS_DYNAMIC_ARRAY_H_
