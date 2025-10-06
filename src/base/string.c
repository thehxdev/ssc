typedef unsigned long long __ssc_word_t;

#define __SSC_WORD_BIT_SIZE         (sizeof(__ssc_word_t) << 3U)
#define __SSC_SHIFT_N_BY            ((__SSC_WORD_BIT_SIZE >> 5U) + 1U)
#define __SSC_LAST_BYTES_ADDR_MASK  ((__SSC_WORD_BIT_SIZE >> 3U) - 1U)

#define __ssc_aligned_copy_info(__buffer, __n)                                          \
    __ssc_word_t *__buffer##_word = (__ssc_word_t*) __buffer;                           \
    __ssc_word_t *__buffer##_word_end = __buffer##_word + ((__n) >> __SSC_SHIFT_N_BY);  \
    uint8_t *__buffer##_byte = (uint8_t*) __buffer##_word_end;                          \
    uint8_t *__buffer##_byte_end = __buffer##_byte + ((__n) & __SSC_LAST_BYTES_ADDR_MASK);


// Copy data in word-size chunks.
void *ssc_memcpy_fast(void *dest, const void *src, size_t n) {
    __ssc_aligned_copy_info(src, n);
    __ssc_aligned_copy_info(dest, n);
    SSC_UNUSED(dest_byte_end);

    while (src_word != src_word_end) {
        *dest_word = *src_word;
        dest_word++;
        src_word++;
    }
    while (src_byte != src_byte_end) {
        *dest_byte = *src_byte;
        dest_byte++;
        src_byte++;
    }

    return dest;
}

void *ssc_memmove_fast(void *dest, const void *src, size_t n) {
    if (dest < src)
        return ssc_memcpy_fast(dest, src, n);

    __ssc_aligned_copy_info(src, n);
    __ssc_aligned_copy_info(dest, n);

    dest_byte_end--;
    dest_word_end--;
    src_byte_end--;
    src_word_end--;

    while (src_byte < src_byte_end) {
        *dest_byte_end = *src_byte_end;
        dest_byte_end--;
        src_byte_end--;
    }
    while (src_word <= src_word_end) {
        *dest_word_end = *src_word_end;
        dest_word_end--;
        src_word_end--;
    }

    return dest;
}
