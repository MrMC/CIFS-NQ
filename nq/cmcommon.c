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
cmWcharToIp(
    NQ_WCHAR *wchar,
    NQ_IPADDRESS *ip
)
{
    static NQ_CHAR ascii[256];
    cmUnicodeToAnsi(ascii, wchar);

    return cmAsciiToIp(ascii, ip);
}

NQ_STATUS
cmIpToAscii(
    NQ_CHAR *ascii,
    const NQ_IPADDRESS *ip
   )
{
	*ascii = '\0';
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
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Invalid ip version: %d", ip->version);
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
    return (NQ_CHAR*)"";
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
    NQ_STATUS res = NQ_FAIL;

    if (!str || *str == '.')
        goto Exit;

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
                goto Exit;

            continue;
        }

        digit = parseDigit(*str++);

        if (digit < 0 || digit > 9)
            goto Exit;

        num = num * 10 + digit;

        if (num > 255)
            goto Exit;
    }

    *tmp = (NQ_BYTE)num;
    counter++;
    if (counter < 4)
        goto Exit;

    /* result is already in BIG ENDIAN, no need to convert to the network order */
    resultIp = (NQ_IPADDRESS4*)result;
    CM_IPADDR_ASSIGN4(*ip, *resultIp);
    res = NQ_SUCCESS;

Exit:
    return res;
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

NQ_BOOL cmIsIPv6Literal(NQ_WCHAR *name)
{
	NQ_WCHAR ipv6LiteralName[] = {cmWChar('.'), cmWChar('i'), cmWChar('p'), cmWChar('v'), cmWChar('6'), cmWChar('-'), cmWChar('l'),
			cmWChar('i'), cmWChar('t'), cmWChar('e'), cmWChar('r'), cmWChar('a'), cmWChar('l'), cmWChar('.'), cmWChar('n'),
			cmWChar('e'), cmWChar('t'), cmWChar('\0')};
	NQ_BOOL res = FALSE;

	/* check whether address is ipv6-literal.net */
	if (cmWStrincmp(name + syWStrlen(name) - syWStrlen(ipv6LiteralName), ipv6LiteralName, (NQ_COUNT)(syWStrlen(ipv6LiteralName))) == 0)
		res = TRUE;

	return res;
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
    NQ_CHAR *last, *input;
    NQ_BOOL mixed;
    NQ_INT zeros, zeroslen, counter, num, limit, digit, i;
    NQ_CHAR ipv6LiteralName[] = ".IPV6-LITERAL.NET";
    NQ_STATUS res = NQ_FAIL;
    NQ_CHAR temp[40];

    /* check whether address is ipv6-literal.net */
    input = str;
    if (syStrlen(str) > syStrlen(ipv6LiteralName) && 
        cmAStrincmp(str + syStrlen(str) - syStrlen(ipv6LiteralName), ipv6LiteralName, (NQ_COUNT)(syStrlen(ipv6LiteralName))) == 0)
    {
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
        input = temp;
    }

    tmp = result;
    last = NULL;
    zeros = -1;
    counter = num = 0;
    mixed = syStrchr(input, '.') != NULL;
    limit = mixed ? 7 : 8 ;

    while (*input)
    {
        if (*input == ':' && input[1] == ':')
        {
            last = ++input;

            if (zeros >= 0)
                goto Exit;

            zeros = counter + 1;
        }

        if (*input == ':')
        {
            last = input;
            *tmp++ = syHton16((NQ_UINT16)num);
            num = 0;
            counter++;
            input++;
            if (counter > (limit - 1) || *input == 0)
                goto Exit;

            continue;
        }

        if (*input == '.' || *input == '%')
            break;

        digit = parseDigit(*input++);

        if (digit < 0)
            goto Exit;

        num = (num << 4) + digit;

        if (num > 0xffff)
            goto Exit;
    }

    *tmp++ = syHton16((NQ_UINT16)num);
    counter++;

    if (counter < limit && zeros < 0)
        goto Exit;

    if (counter == limit && zeros >= 0)
        goto Exit;

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
            goto Exit;

        syMemcpy(&result[6], &ip4.addr.v4, sizeof(NQ_IPADDRESS4));
    }

    CM_IPADDR_ASSIGN6(*ip, *(NQ_IPADDRESS6*)result);
    res = NQ_SUCCESS;

Exit:
    return res;
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
    for (i = 0; i < (NQ_INT)NQ_IPADDRESS6_WORDS; i = j + 1)
    {
        for (j = i; j < (NQ_INT)NQ_IPADDRESS6_WORDS && !ip6[j]; j++);

        if ((j - i) > zeroslen)
        {
            zeros = i;
            zeroslen = j - i;
        }
    }

    for (i = 0; i < (NQ_INT)NQ_IPADDRESS6_WORDS;)
    {
        if (i == zeros)
        {
            syStrcat(ascii, i ? ":" : "::");
            i += zeroslen;
            continue;
        }

        sySprintf(str, "%x", syNtoh16(ip6[i]));
        if (++i < (NQ_INT)NQ_IPADDRESS6_WORDS)
            syStrcat(str, ":");

        syStrcat(ascii, str);
    }

    return NQ_SUCCESS;
}
#endif /* UD_NQ_USETRANSPORTIPV6 */

