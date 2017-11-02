/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : The most basic definitions, common for all NQ modules
 *                 (this source assumes that system-dependent defintions
 *                 were not defined yet)
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 21-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMCOMMON_H_
#define _CMCOMMON_H_

#ifndef NQ_SUCCESS
#define NQ_SUCCESS  (0)
#endif

#ifndef NQ_FAIL
#define NQ_FAIL     (-1)
#endif

#define CM_IPADDR_IPV4 4
#ifdef UD_NQ_USETRANSPORTIPV6
#define CM_IPADDR_IPV6 6

#define CM_IPADDR_MAXLEN 46 /* max lenght of textual representation + trailing null */
#define CM_IPADDR_ZERO   {0, {SY_ZEROIP}}
#define CM_IPADDR_ANY4   {CM_IPADDR_IPV4, {SY_ANYIP4}}
#define CM_IPADDR_ANY6   {CM_IPADDR_IPV6, {SY_ANYIP6}}
#define CM_IPADDR_LOCAL  {CM_IPADDR_IPV4, {SY_LOCALHOSTIP4}}
#define CM_IPADDR_LOCAL6 {CM_IPADDR_IPV6, {SY_LOCALHOSTIP6}}

#define CM_IPADDR_VERSION(_addr) (_addr).version
#define CM_IPADDR_SIZE(_addr) \
    (((_addr).version == CM_IPADDR_IPV6) \
    ? sizeof(NQ_IPADDRESS6) \
    : (((_addr).version == CM_IPADDR_IPV4) ? sizeof(NQ_IPADDRESS4) : 0))
#define CM_IPADDR_GET4(_addr) (_addr).addr.v4
#define CM_IPADDR_GET6(_addr) (_addr).addr.v6
#define CM_IPADDR_ASSIGN4(_addr, _ip4) \
    {(_addr).version = CM_IPADDR_IPV4; (_addr).addr.v4 = _ip4;}
#define CM_IPADDR_ASSIGN6(_addr, _ip6) \
    {(_addr).version = CM_IPADDR_IPV6; syMemcpy((_addr).addr.v6, _ip6, sizeof(NQ_IPADDRESS6));}
#define CM_IPADDR_EQUAL4(_addr, _other) \
    ((_addr).version == CM_IPADDR_IPV4 && (_addr).addr.v4 == _other)
#define CM_IPADDR_EQUAL6(_addr, _other) \
    ((_addr).version == CM_IPADDR_IPV6 && \
    (syMemcmp((_addr).addr.v6, _other, sizeof(NQ_IPADDRESS6)) == 0))
#define CM_IPADDR_EQUAL(_addr, _other) \
    ((_addr).version == (_other).version && ((_addr).version == CM_IPADDR_IPV4 \
        ? ((_addr).addr.v4 == (_other).addr.v4) \
        : (syMemcmp((_addr).addr.v6, (_other).addr.v6, sizeof(NQ_IPADDRESS6)) == 0)))

#else /* UD_NQ_USETRANSPORTIPV6 */

#define CM_IPADDR_MAXLEN 16 /* max lenght of textual representation + trailing null */
#define CM_IPADDR_ZERO  SY_ZEROIP
#define CM_IPADDR_ANY4  SY_ANYIP
#define CM_IPADDR_LOCAL SY_LOCALHOSTIP

#define CM_IPADDR_VERSION(_addr)       CM_IPADDR_IPV4
#define CM_IPADDR_SIZE(_addr)          sizeof(NQ_IPADDRESS4)
#define CM_IPADDR_GET4(_addr)          (_addr)
#define CM_IPADDR_ASSIGN4(_addr, _other)  ((_addr) = (_other))
#define CM_IPADDR_EQUAL4(_addr, _other) ((_addr) == (_other))
#define CM_IPADDR_EQUAL(_addr, _other)    ((_addr) == (_other))

#endif /* UD_NQ_USETRANSPORTIPV6 */

#define CM_IPADDR_ZERO4 SY_ZEROIP4


#ifndef SY_PACK_ATTR
#define SY_PACK_ATTR
#endif

#ifndef SY_PACK_PREFIX
#define SY_PACK_PREFIX
#endif

NQ_STATUS
cmAsciiToIp(
    NQ_CHAR *ascii,
    NQ_IPADDRESS *ip
   );

NQ_STATUS
cmIpToAscii(
    NQ_CHAR *ascii,
    const NQ_IPADDRESS *ip
   );


NQ_CHAR*
cmIPDump(
    const NQ_IPADDRESS *ip
    );

/* abstract blob */
typedef struct
{
    NQ_BYTE* data;  /* data pointer */
    NQ_COUNT len;   /* data length */
}
CMBlob;

/**** Virtual "static" definition.
 * Virtual static always designates a function-scope
 * variable. Depending on project decision it may be
 * compiled as either automatic or static.
 * Static variables save stack room but require more
 * RAM.
 */

#ifdef SY_BIGSTACK
#define NQ_STATIC                 /* defined as automatic */
#else
#define NQ_STATIC    static       /* defined as static */
#endif

#define CM_ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#endif  /* _CMCOMMON_H_ */
