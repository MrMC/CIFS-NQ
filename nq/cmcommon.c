/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Common part of common library
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 31-Oct-2005
 * CREATED BY    : Alexey Yarovinsky
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "nsapi.h"

static
NQ_INT
parseDigit(
    NQ_CHAR ch
    );

static
NQ_STATUS
cmAsciiToIp4(
    NQ_CHAR *str,
    NQ_IPADDRESS *ip
   );

static
NQ_STATUS
cmIpToAscii4(
    NQ_CHAR *ascii,
    NQ_IPADDRESS4 ip
   );

#ifdef UD_NQ_USETRANSPORTIPV6

static
NQ_STATUS
cmAsciiToIp6(
    NQ_CHAR *str,
    NQ_IPADDRESS *ip
   );

static
NQ_STATUS
cmIpToAscii6(
    NQ_CHAR *ascii,
    const NQ_IPADDRESS *ip
   );

#endif /* UD_NQ_USETRANSPORTIPV6 */

NQ_STATUS
cmAsciiToIp(
    NQ_CHAR *ascii,
    NQ_IPADDRESS *ip
   )
{
    if (cmAsciiToIp4(ascii, ip) == NQ_SUCCESS)
        return NQ_SUCCESS;

#ifdef UD_NQ_USETRANSPORTIPV6
    if (cmAsciiToIp6(ascii, ip) == NQ_SUCCESS)
        return NQ_SUCCESS;
#endif /* UD_NQ_USETRANSPORTIPV6 */

    return NQ_FAIL;
}

NQ_STATUS
cmIpToAscii(
    NQ_CHAR *ascii,
    const NQ_IPADDRESS *ip
   )
{
#ifdef UD_NQ_USETRANSPORTIPV6
    switch (CM_IPADDR_VERSION(*ip))
    {
        case CM_IPADDR_IPV4:
#endif /* UD_NQ_USETRANSPORTIPV6 */
            return cmIpToAscii4(ascii, CM_IPADDR_GET4(*ip));

#ifdef UD_NQ_USETRANSPORTIPV6
        case CM_IPADDR_IPV6:
            return cmIpToAscii6(ascii, ip);

        default:
            TRC1P("Invalid ip version: %d", ip->version);
            *ascii = '\0';  /* cleanup */
            return NQ_FAIL;
    }
#endif /* UD_NQ_USETRANSPORTIPV6 */
}

NQ_CHAR*
cmIPDump(
    const NQ_IPADDRESS *ip
    )
{
#if SY_DEBUGMODE
    static NQ_CHAR temp[CM_IPADDR_MAXLEN];

    cmIpToAscii(temp, ip);
    return temp;
#else
    return "";
#endif
}

static
NQ_INT
parseDigit(
    NQ_CHAR ch
    )
{
    switch (ch)
    {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return ch - '0';

#ifdef UD_NQ_USETRANSPORTIPV6
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        return ch - 'a' + 10;

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
        return ch - 'A' + 10;
#endif /* UD_NQ_USETRANSPORTIPV6 */

    default:
        return -1;
    }
}

static
NQ_STATUS
cmAsciiToIp4(
    NQ_CHAR *str,
    NQ_IPADDRESS *ip
   )
{
    NQ_BYTE result[4];
    NQ_BYTE *tmp = result;
    NQ_INT counter, digit, num;
    NQ_IPADDRESS4 *resultIp;

    if (!str || *str == '.')
        return NQ_FAIL;

    counter = num = 0;

    while (*str)
    {
        if (*str == '.')
        {
            *tmp++ = (NQ_BYTE)num;
            num = 0;
            counter++;
            str++;
            if (counter > 3 || *str == 0 || *str == '.')
                return NQ_FAIL;

            continue;
        }

        digit = parseDigit(*str++);

        if (digit < 0 || digit > 9)
            return NQ_FAIL;

        num = num * 10 + digit;

        if (num > 255)
            return NQ_FAIL;
    }

    *tmp = (NQ_BYTE)num;
    counter++;
    if (counter < 4)
        return NQ_FAIL;

    /* result is already in BIG ENDIAN, no need to convert to the network order */
    resultIp = (NQ_IPADDRESS4*)result;
    CM_IPADDR_ASSIGN4(*ip, *resultIp);

    return NQ_SUCCESS;
}

static
NQ_STATUS
cmIpToAscii4(
    NQ_CHAR *ascii,
    NQ_IPADDRESS4 ip
   )
{
    NQ_UINT32 i = syNtoh32((NQ_UINT)ip);

    sySprintf(
        ascii,
        "%u.%u.%u.%u",
        (NQ_INT)((i >> 24) & 0xff),
        (NQ_INT)((i >> 16) & 0xff),
        (NQ_INT)((i >> 8) & 0xff),
        (NQ_INT)(i & 0xff));

    return NQ_SUCCESS;
}

#ifdef UD_NQ_USETRANSPORTIPV6

#define NQ_IPADDRESS6_WORDS sizeof(NQ_IPADDRESS6)/2

static
NQ_STATUS
cmAsciiToIp6(
    NQ_CHAR *str,
    NQ_IPADDRESS *ip
   )
{
    NQ_IPADDRESS6 result = { 0, 0, 0, 0, 0, 0, 0, 0 };
    NQ_IPADDRESS ip4;
    NQ_UINT16 *tmp;
    NQ_CHAR *last;
    NQ_BOOL mixed;
    NQ_INT zeros, zeroslen, counter, num, limit, digit, i;
    NQ_CHAR ipv6LiteralName[] = ".IPV6-LITERAL.NET";

    /* check whether address is ipv6-literal.net */
    if (syStrlen(str) > syStrlen(ipv6LiteralName) && 
        cmAStrincmp(str + syStrlen(str) - syStrlen(ipv6LiteralName), ipv6LiteralName, (NQ_COUNT)(syStrlen(ipv6LiteralName))) == 0)
    {
        NQ_STATIC NQ_CHAR temp[40];
        NQ_CHAR *p;
        NQ_COUNT i;
        
        for (i = 0, p = str; *p != '.'; p++, i++)
        {
            switch (*p)
            {
                case '-':
                    temp[i] = ':';
                    break;
                case 'S':
                case 's':
                    temp[i] = '%';
                    break;
                default:
                    temp[i] = *p;
                    break;                   
            }
        }
        temp[i] = '\0';
        str = temp;
    }

    tmp = result;
    last = NULL;
    zeros = -1;
    counter = num = 0;
    mixed = syStrchr(str, '.') != NULL;
    limit = mixed ? 7 : 8 ;

    while (*str)
    {
        if (*str == ':' && str[1] == ':')
        {
            last = ++str;

            if (zeros >= 0)
                return NQ_FAIL;

            zeros = counter + 1;
        }

        if (*str == ':')
        {
            last = str;
            *tmp++ = syHton16((NQ_UINT16)num);
            num = 0;
            counter++;
            str++;
            if (counter > (limit - 1) || *str == 0)
                return NQ_FAIL;

            continue;
        }

        if (*str == '.' || *str == '%')
            break;

        digit = parseDigit(*str++);

        if (digit < 0)
            return NQ_FAIL;

        num = (num << 4) + digit;

        if (num > 0xffff)
            return NQ_FAIL;
    }

    *tmp++ = syHton16((NQ_UINT16)num);
    counter++;

    if (counter < limit && zeros < 0)
        return NQ_FAIL;

    if (counter == limit && zeros >= 0)
        return NQ_FAIL;

    if (zeros >= 0 )
    {
        zeroslen = limit - counter;

        for (i = limit - 1; i >= (zeros + zeroslen); i--)
        {
            result[i] = result[i - zeroslen];
            result[i - zeroslen] = 0;
        }
    }

    if (mixed)
    {
        if (cmAsciiToIp4(last + 1, &ip4) == NQ_FAIL)
            return NQ_FAIL;

        syMemcpy(&result[6], &ip4.addr.v4, sizeof(NQ_IPADDRESS4));
    }

    CM_IPADDR_ASSIGN6(*ip, *(NQ_IPADDRESS6*)result);

    return NQ_SUCCESS;
}

static
NQ_STATUS
cmIpToAscii6(
    NQ_CHAR *ascii,
    const NQ_IPADDRESS *ip
   )
{
    NQ_IPADDRESS6 ip6;
    NQ_INT zeros, zeroslen, i, j;
    NQ_CHAR str[8];

    syMemcpy(ip6, ip->addr.v6, sizeof(NQ_IPADDRESS6));
    *ascii = 0;
    zeros = -1;
    zeroslen = 1;
    for (i = 0; i < NQ_IPADDRESS6_WORDS; i = j + 1)
    {
        for (j = i; j < NQ_IPADDRESS6_WORDS && !ip6[j]; j++);

        if ((j - i) > zeroslen)
        {
            zeros = i;
            zeroslen = j - i;
        }
    }

    for (i = 0; i < NQ_IPADDRESS6_WORDS;)
    {
        if (i == zeros)
        {
            syStrcat(ascii, i ? ":" : "::");
            i += zeroslen;
            continue;
        }

        sySprintf(str, "%x", syNtoh16(ip6[i]));
        if (++i < NQ_IPADDRESS6_WORDS)
            syStrcat(str, ":");

        syStrcat(ascii, str);
    }

    return NQ_SUCCESS;
}
#endif /* UD_NQ_USETRANSPORTIPV6 */

