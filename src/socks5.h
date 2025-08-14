#ifndef _SSC_SOCKS5_H_
#define _SSC_SOCKS5_H_

enum {
    SOCKS5_Version  = 0x05,
    SOCKS5_Reserved = 0x00
};

// address type
enum {
    SOCKS5_ATYPE_IPV4 = 0x01,
    SOCKS5_ATYPE_FQDN = 0x03,
    SOCKS5_ATYPE_IPV6 = 0x04
};

// command
enum {
    SOCKS5_Connect   = 0x01,
    SOCKS5_Bind      = 0x02,
    SOCKS5_Associate = 0x03
};

// authentication method
enum {
    SOCKS5_NoAuth =  0x00,
    SOCKS5_NoAcceptableMethods = 0xff
};

// error codes
enum {
    SOCKS5_Ok = 0x00,
    SOCKS5_GeneralServerFailure,
    SOCKS5_ConnectionNotAllowed,
    SOCKS5_NetworkUnreachable,
    SOCKS5_HostUnreachable,
    SOCKS5_ConnectionRefused,
    SOCKS5_TTLExpired,
    SOCKS5_CommandNotSupported,
    SOCKS5_AddressTypeNotSupported,
};

#endif // _SSC_SOCKS5_H_
