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

/*@@CM_IPADDR_VERSION
   Description
   Get IP address type.
   
   This call allows determining the concrete type of an abstract
   IP address.
   Parameters
   _addr :  IP address
   Returns
   CM_IPADDR_IPV4 or CM_IPADDR_IPV6 (see <link Other Constants>). */
#define CM_IPADDR_VERSION(_addr) (_addr).version

/*@@CM_IPADDR_SIZE
   Description
   Get the actual size of an IP address.
   
   This call returns the number of bytes needed to hold the
   actual address.
   Parameters
   _addr :  IP address. 
   Returns
   Actual size of the address.                              */
#define CM_IPADDR_SIZE(_addr) \
    (((_addr).version == CM_IPADDR_IPV6) \
    ? sizeof(NQ_IPADDRESS6) \
    : (((_addr).version == CM_IPADDR_IPV4) ? sizeof(NQ_IPADDRESS4) : 0))

/*@@CM_IPADDR_GET4
   Description
   Withdraw an IPv4 address from an abstract IP address.
   
   An IPv4 address as a loadable value.
   Parameters
   _addr :  IP address. 
   Returns
   IPv4 address.                                         */
#define CM_IPADDR_GET4(_addr) (_addr).addr.v4

/*@@CM_IPADDR_GET6
   Description
   Withdraw an IPv6 address from an abstract IP address.
   
   An IPv6 address as a pointer.
   Parameters
   _addr :  IP address. 
   Returns
   IPv6 address as a pointer.                            */
#define CM_IPADDR_GET6(_addr) (_addr).addr.v6

/*@@CM_IPADDR_ASSIGN4
   Description
   Set an abstract IP address as IPv4 address.
   Parameters
   _addr :  Pointer to an abstract IP address.
   _ip4 :   IPv4 address to assign to the abstract IP address.
   Returns
   None                                                        */
#define CM_IPADDR_ASSIGN4(_addr, _ip4) \
    {(_addr).version = CM_IPADDR_IPV4; (_addr).addr.v4 = _ip4;}

/*@@CM_IPADDR_ASSIGN6
   Description
   Set an abstract IP address as IPv6 address.
   Parameters
   _addr :  Pointer to an abstract IP address.
   _ip4 :   Pointer to IPv6 address to assign to the abstract IP
            address.
   Returns
   None                                                          */
#define CM_IPADDR_ASSIGN6(_addr, _ip6) \
    {(_addr).version = CM_IPADDR_IPV6; syMemcpy((_addr).addr.v6, _ip6, sizeof(NQ_IPADDRESS6));}

/*@@CM_IPADDR_EQUAL4
   Description
   Compare an abstract IP address with an IPv4 address.
   
   To match, he abstract address should be of the IPv4 type and
   its address value should match the IPv4 address.
   Parameters
   _addr :  Pointer to the abstract IP address.
   _ip4 :   IPv4 address to compare with.
   Returns
   <i>TRUE</i> when abstract IP address is the same as the IPv4
   address, <i>FALSE</i> otherwise.                             */
#define CM_IPADDR_EQUAL4(_addr, _other) \
    ((_addr).version == CM_IPADDR_IPV4 && (_addr).addr.v4 == _other)

/*@@CM_IPADDR_EQUAL6
   Description
   Compare an abstract IP address with an IPv6 address.
   
   To match, the abstract address should be of the IPv6 type and
   its address value should match the IPv6 address.
   Parameters
   _addr :  Pointer to the abstract IP address.
   _ip6 :   Pointer to the IPv6 address to compare with.
   Returns
   <i>TRUE</i> when abstract IP address is the same as the IPv6
   address, <i>FALSE</i> otherwise.                              */
#define CM_IPADDR_EQUAL6(_addr, _other) \
    ((_addr).version == CM_IPADDR_IPV6 && \
    (syMemcmp((_addr).addr.v6, _other, sizeof(NQ_IPADDRESS6)) == 0))

/*@@CM_IPADDR_EQUAL
   Description
   Compare two abstract IP addresses.
   
   Both abstract addresses are equal when they are of the same
   type and their address values are equal.
   Parameters
   _addr :   First IP address.
   _other :  Second IP address.
   Returns
   <i>TRUE</i> when both addresses are equal, <i>FALSE</i>
   otherwise.                                                  */
#define CM_IPADDR_EQUAL(_addr, _other) \
    ((_addr).version == (_other).version && ((_addr).version == CM_IPADDR_IPV4 \
        ? ((_addr).addr.v4 == (_other).addr.v4) \
        : (syMemcmp((_addr).addr.v6, (_other).addr.v6, sizeof(NQ_IPADDRESS6)) == 0)))

/*@@INT_TO_ADDR4
   Description
   Generate INT to 4 INTs = IP address.

   Parameters
   _addr :   First IP address v4.
   Returns
   None                                                  */
#define INT_TO_ADDR4(_addr) \
(_addr & 0xFF), \
(_addr >> 8 & 0xFF), \
(_addr >> 16 & 0xFF), \
(_addr >> 24 & 0xFF)

#else /* UD_NQ_USETRANSPORTIPV6 */

#define CM_IPADDR_MAXLEN 16 /* max length of textual representation + trailing null */
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

/*@@cmAsciiToIp@NQ_CHAR *@NQ_IPADDRESS *
   Description
   Convert ASCII string representation of IP address into an abstract
   IP structure.
   
   This function converts IP address according to its type.
   Parameters
   str :   String containing text representation of IP address.
   addr :  IP address/
   Returns
   <i>NQ_SUCCESS</i> when conversion was done, <i>NQ_FAIL</i>
   otherwise.                                                   */
NQ_STATUS cmAsciiToIp(NQ_CHAR *ascii, NQ_IPADDRESS *ip);

/*@@cmWcharToIp@NQ_WCHAR *@NQ_IPADDRESS *
    Description
    Convert WCHAR string representation of IP address into an abstract
    IP structure.

    This function converts IP address according to its type.
    Parameters
    str :   String containing text representation of IP address.
    addr :  IP address/
    Returns
    <i>NQ_SUCCESS</i> when conversion was done, <i>NQ_FAIL</i>
    otherwise.                                                   */
NQ_STATUS cmWcharToIp(NQ_WCHAR *wchar, NQ_IPADDRESS *ip);

 /*@@cmIpToAscii@NQ_CHAR *@NQ_IPADDRESS *
    Description
    Convert an abstract IP address into printable text
    representation.
    
    This function converts IP address according to its type.
    Parameters
    buffer :  Text buffer of enough size.
    addr :    the IP address to convert.
    Returns
    <i>NQ_SUCCESS</i> when conversion was done, <i>NQ_FAIL</i>
    otherwise                                                  */
NQ_STATUS cmIpToAscii(NQ_CHAR *ascii, const NQ_IPADDRESS *ip);

/*@@cmIsIPv6Literal@NQ_WCHAR *
    Description
    checks if a received string is an upv6 literal/

    this function checks a string name suffix
    if equal to "ipv6.literal".

    Returns
    <i>TRUE</i> when name is ipv6 literal, <i>FALSE</i>
    otherwise                                                  */
NQ_BOOL cmIsIPv6Literal(NQ_WCHAR *name);

/*@@cmIPDump@NQ_IPADDRESS *
   Description
   Converts IP address to a text representation into an embedded
   buffer.
   
   This function converts IP address according to its type.
   Since the result resides in a static buffer this function
   should not be used twice as a parameter in a printf call.
   This function is not thread-safe.
   Parameters
   buffer :  Text buffer of enough size.
   addr :    the IP address to convert.
   Returns
   Pointer to the string representation of the provided IP.      */
NQ_CHAR * cmIPDump(const NQ_IPADDRESS *ip);

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
