#ifndef _SSC_SS_SS_H_
#define _SSC_SS_SS_H_

SSC_PACKED(struct ssc_fixed_header {
    uint8_t type;
    uint64_t timestamp;
    uint16_t length;
});
typedef struct ssc_fixed_header ssc_fixed_header_t;

#endif // _SSC_SS_SS_H_
