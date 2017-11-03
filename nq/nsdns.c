/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Light-weight DNS client
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets 
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 31-Oct-2005
 * CREATED BY    : Alexey Yarovinsky
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "udparams.h"
#include "nsapi.h"
#include "cmresolver.h"
#include "cmbuf.h"
#include "amapi.h"
#include "nsdns.h"

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)

typedef struct
{
    NQ_CHAR dnsDomain[CM_NQ_HOSTNAMESIZE + 1];
    NQ_IPADDRESS dnsServers[UD_NQ_MAXDNSSERVERS * UD_NS_MAXADAPTERS];
    NQ_COUNT numServers;
    NQ_UINT16 id;
    NQ_IPADDRESS llmnrIp4;
    NQ_IPADDRESS llmnrIp6;
    SYMutex guard;
    NQ_BOOL isRegistered;
    NQ_BOOL isNewServerSet;   /* boolean to check is cmDnsSetServers has been called*/
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

typedef struct  /* secure exchange data */
{
    const NQ_IPADDRESS * ip;            /* server IP */
    SYSocketHandle socket;              /* TCP socket */
    CMBlob tkey;                        /* TKEY */
    NQ_INT originalIdOffset;            /* offset from in tkey to original ID field */
    NQ_CHAR name[100];                  /* TKEY name */
    CMBlob sessionKey;                  /* not used - for compatibility with GSSAPI */
    CMBlob macKey;                      /* not used - for compatibility with GSSAPI */
} 
TkeyContext;

/* -- Static functions -- */

#ifndef UD_CM_DONOTREGISTERHOSTNAMEDNS
/* Place new record ID in the "Original ID' field of TKEY */
static void setTkeyOriginalId(const TkeyContext * pTkey, NQ_UINT16 id)
{
    CMRpcPacketDescriptor writer;       /* to pack data */

    cmRpcSetDescriptor(&writer, (NQ_BYTE *)pTkey->tkey.data + pTkey->originalIdOffset, TRUE);
    cmRpcPackUint16(&writer, id);
}
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */

/* pack DNS header */
void nsWriteDnsHeader(CMRpcPacketDescriptor * writer, const DnsHeader * pHeader)
{
    cmRpcPackUint16(writer, pHeader->id);
    cmRpcPackByte(writer, pHeader->flags1);
    cmRpcPackByte(writer, pHeader->flags2);
    cmRpcPackUint16(writer, pHeader->questions);
    cmRpcPackUint16(writer, pHeader->answers);
    cmRpcPackUint16(writer, pHeader->authority);
    cmRpcPackUint16(writer, pHeader->additional);
}

/* parse DNS header */
void nsReadDnsHeader(CMRpcPacketDescriptor * reader, DnsHeader * pHeader)
{
    cmRpcParseUint16(reader, &pHeader->id);
    cmRpcParseByte(reader, &pHeader->flags1);
    cmRpcParseByte(reader, &pHeader->flags2);
    cmRpcParseUint16(reader, &pHeader->questions);
    cmRpcParseUint16(reader, &pHeader->answers);
    cmRpcParseUint16(reader, &pHeader->authority);
    cmRpcParseUint16(reader, &pHeader->additional);
}

/* encode fully qualified name as DNS string */
void nsDnsEncodeName(CMRpcPacketDescriptor * writer, const NQ_CHAR *name)
{
    NQ_CHAR *s;     /* pointer in string */
    NQ_UINT length; /* next segment length */

    do
    {
        s = (NQ_CHAR *)syStrchr(name, '.');
        length = (NQ_UINT)(s ? (NQ_UINT)(s - name) : syStrlen(name));
        cmRpcPackByte(writer, (NQ_BYTE)length);
        cmRpcPackBytes(writer, (NQ_BYTE *)name, length);
        name = s + 1;
    }
    while (s);

    cmRpcPackByte(writer, 0);
    return;
}

/* convert DNS string into fully qualified name */
NQ_STATUS nsDnsDecodeName(CMRpcPacketDescriptor * reader, NQ_CHAR * name)
{
    NQ_BYTE * p;        /* pointer in DNS string */
    NQ_BOOL jump;       /* jump indicator */
    NQ_UINT length;     /* segment length */
	NQ_CHAR * t;        /* pointer in name string */

	if (name)
	{
		*name = '\0';
		t = name;
	}

    jump = FALSE;
    for (p = cmBufferReaderGetPosition(reader); *p != '\0'; )
    {
        if (*p == 0xc0 && !jump)
        {
            p = cmBufferReaderGetStart(reader) + p[1];
            jump = TRUE;
            cmBufferReaderSkip(reader, 2);
            continue;
        }

        length = *p++;
		if (name)
		{
			syStrncat((NQ_CHAR*)name, (NQ_CHAR*)p, length);
			t += length;
		}
        p += length;
		if (name && *p)
		{
			syStrcat((NQ_CHAR*)name, ".");
			t++;
		}
        if (!jump)
            cmBufferReaderSkip(reader, length + 1);
    }
	if (name)
		*t = '\0';

    if (!jump)
        cmBufferReaderSkip(reader, 1);
    return NQ_SUCCESS;
}

/* add domain name to a name if it is not FQ */
static void dnsNormalizeName(const NQ_CHAR * host, NQ_CHAR *tmp)
{
    NQ_IPADDRESS ip;    /* dummy */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "host:%p tmp:%p", host, tmp);

    if (NQ_SUCCESS == cmAsciiToIp((NQ_CHAR *)host + 2, &ip))
    {
        goto Exit;
    }
    syStrncpy(tmp, host, CM_NQ_HOSTNAMESIZE);
    if (!syStrchr(tmp, '.'))
    {
        if (CM_NQ_HOSTNAMESIZE >= syStrlen(tmp) + syStrlen(staticData->dnsDomain) + 1)
        {
            syStrcat(tmp, ".");
            syStrcat(tmp, staticData->dnsDomain);
        }
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* create a reverse-order ASCII representation of IP address
   a new string is allocated and the caller should free it
*/
NQ_CHAR * nsDnsCreateReversedName(const NQ_IPADDRESS * ip)
{
    NQ_CHAR * buffer;           /* buffer to compose name */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "ip:%p", ip);
    buffer = (NQ_CHAR *)cmMemoryAllocate(CM_DNS_NAMELEN + 1);
    if (NULL == buffer)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    buffer[0] = '\0';

    switch (CM_IPADDR_VERSION(*ip))
    {
#ifdef UD_NQ_USETRANSPORTIPV4
    case CM_IPADDR_IPV4:
        {
            NQ_CHAR ipBuffer[CM_IPADDR_MAXLEN]; /* for converting IP into ascii */
            NQ_CHAR * p;                        /* pointer inside */

            cmIpToAscii(ipBuffer, ip);
            for (p = syStrrchr(ipBuffer, '.'); p != NULL ; p = syStrrchr(ipBuffer, '.'))
            {
                syStrcat(buffer, p + 1);
                syStrcat(buffer, ".");
                *p = '\0';
            }
            syStrcat(buffer, ipBuffer);
            syStrcat(buffer, ".in-addr.arpa");
        }
        break;
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    case CM_IPADDR_IPV6:
        {
            NQ_INT i;               /* octet index in IPv6 */
            NQ_CHAR * p = buffer;   /* pointer inside the buffer */
            const NQ_CHAR hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

            for (i = 7; i >= 0; i--)
            {
                *p++ = hex[ip->addr.v6[i] >> 8 & 0xf];
                *p++ = '.';
                *p++ = hex[ip->addr.v6[i] >> 12 & 0xf];
                *p++ = '.';
                *p++ = hex[ip->addr.v6[i] & 0xf];
                *p++ = '.';
                *p++ = hex[ip->addr.v6[i] >> 4 & 0xf];
                *p++ = '.';
            }
            *p = '\0';
            syStrcat(buffer, "ip6.arpa");
        }
        break;
#endif /* UD_NQ_USETRANSPORTIPV6 */
    default:
        cmMemoryFree(buffer);
        buffer = NULL;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", buffer);
    return buffer;
}



NQ_IPADDRESS *  nsDnsParseReversedName(NQ_CHAR * name , NQ_UINT16 type)
{
	NQ_IPADDRESS * resIp = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p type:%u", name, type);

	resIp = (NQ_IPADDRESS *)cmMemoryAllocate(sizeof(NQ_IPADDRESS));
    if (NULL == resIp)
    {
        goto Exit;
    }

	switch (type)
	{
#ifdef UD_NQ_USETRANSPORTIPV4
	case CM_IPADDR_IPV4:
		{
			NQ_CHAR ipBuffer[CM_IPADDR_MAXLEN]; /* for converting IP into ascii */
			NQ_CHAR * p;                        /* pointer inside */            
#define IPV4_REVERSED_NAME ".in-addr.arpa"

            p = name + syStrlen(name) - syStrlen(IPV4_REVERSED_NAME);
            if (syStrcmp(p, IPV4_REVERSED_NAME) != 0)
            {
                cmMemoryFree(resIp);
                resIp = NULL;
                break;
            }

			p = syStrchr(name , 'i');
			p--;
			syMemset(p , 0 , syStrlen(IPV4_REVERSED_NAME));
			syMemset(ipBuffer , 0 ,CM_IPADDR_MAXLEN );

			for (p = syStrrchr(name, '.'); p != NULL ; p = syStrrchr(name, '.'))
			{
				syStrcat(ipBuffer, p + 1);
				syStrcat(ipBuffer, ".");
				*p = '\0';
			}
			syStrcat(ipBuffer, name);
			cmAsciiToIp(ipBuffer , resIp);

		}
		break;
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
	case CM_IPADDR_IPV6:
		{

			NQ_INT i;               /* octet index in IPv6 */
			NQ_CHAR   ipBuffer[CM_DNS_NAMELEN + 1];
			NQ_CHAR * p , * pt;   /* pointer inside the buffer */

			p = syStrchr(name , 'i');
			p--;
			p--;
			pt = ipBuffer;
			syMemset(p , 0 , syStrlen("ip6.arpa"));
			for (i = 7; i >= 0; i--)
			{
				*pt++ = *p;
				p--;
				*pt++ = *p;
				p--;
				*pt++ = *p;
				p--;
				*pt++ = *p;
				p--;
				*pt++ = ':';
			}
			cmAsciiToIp(ipBuffer , resIp);
		}
		break;
#endif /* UD_NQ_USETRANSPORTIPV6 */
	default:
		cmMemoryFree(resIp);
		resIp = NULL;
	}

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", resIp);
    return resIp;
}
static void writeBlock(CMRpcPacketDescriptor * writer, const NQ_CHAR * string, const NQ_BYTE * pad, NQ_COUNT sizeOfPad)
{
    nsDnsEncodeName(writer, string);
    cmRpcPackBytes(writer, pad, sizeOfPad);
}

void nsDnsWriteAnswer(CMRpcPacketDescriptor * writer, const NQ_CHAR * string, NQ_UINT16 type , void * answer , NQ_UINT16 answerLen)
{
	nsDnsEncodeName(writer , string);
	cmRpcPackUint16(writer , type);
	cmRpcPackUint16(writer , 0x01);
	cmRpcPackUint32(writer , 0); /* Time To Live set to 0*/
	cmRpcPackUint16(writer , answerLen);
	switch (type)
	{
		case NS_DNS_A:
		{
			NQ_UINT32	* ipAns;

			ipAns = (NQ_UINT32 *)answer;
			cmBufferWriteUint32(writer, syHton32(*ipAns));
			break;
		}
		case NS_DNS_PTR:
		{
			nsDnsEncodeName(writer , (const NQ_CHAR *)answer);
			break;
		}
	}
}

static NQ_COUNT dnsCreateQueryRequest(
    NQ_BYTE * buffer,
    NQ_BYTE type,
    const NQ_CHAR * name
    )
{
    /* predefined DNS blocks */
    NQ_BYTE query[] = {0, 0, 0, 0x01};
    DnsHeader header;                       /* header */
    CMRpcPacketDescriptor writer;           /* packet writer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buffer:%p type:0x%x name:%s", buffer, type, name);

    cmRpcSetDescriptor(&writer, buffer, TRUE);
    syMutexTake(&staticData->guard);
    header.id = ++staticData->id;
    syMutexGive(&staticData->guard);
    header.flags1 = DNS_QUERY;
    header.flags2 = 0;
    header.questions = 1;
    header.answers = 0;
    header.authority = 0;
    header.additional = 0;

    query[1] = type;
    nsWriteDnsHeader(&writer, &header);
    writeBlock(&writer, name, query, sizeof(query));

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (writer.current - writer.origin));
    return (NQ_COUNT)(writer.current - writer.origin);
}

static
NQ_STATUS
dnsParseQueryResponse(
    const NQ_BYTE * buffer,
    const NQ_BYTE type,
    const NQ_CHAR * host,
    NQ_IPADDRESS * ip,
    NQ_INT * pNumIps,
    NQ_CHAR * name
    )
{
    DnsHeader header;               /* header */
    CMRpcPacketDescriptor reader;   /* for parsing */
    NQ_INT i;                       /* just a counter */
    NQ_INT answer = 0;              /* current answer */
	NQ_COUNT length = 0;            /* string length */
    NQ_COUNT maxIps = 0;            /* maximum room in IPs */
    NQ_STATUS res = NQ_FAIL;        /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buffer:%p type:0x%x host:%p ip:%p pNumIps:%p name:%p", buffer, type, host, ip, pNumIps, name);

    if (NULL != pNumIps)
    {
        maxIps = (NQ_COUNT)*pNumIps;
        *pNumIps = 0;
    }
    cmRpcSetDescriptor(&reader, (NQ_BYTE *)buffer, TRUE);
    nsReadDnsHeader(&reader, &header);

    if (DNS_REPLY_CODE_REFUSED == (header.flags2 & DNS_REPLY_CODE))
    {
        /* force secure exchange */
        LOGERR(CM_TRC_LEVEL_ERROR, "DNS_REPLY_CODE_REFUSED");
        res = NQ_ERR_ACCESS;
        goto Exit;
    }
    if (header.answers < 1 || DNS_REPLY_CODE_NO_SUCH_NAME == (header.flags2 & DNS_REPLY_CODE))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "answers:%u, flags2:%d", header.answers, header.flags2);
        goto Exit;
    }
    for (i = header.questions; --i >= 0;)
    {
        if (nsDnsDecodeName(&reader, NULL) == NQ_FAIL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "nsDnsDecodeName() failed");
            goto Exit;
        }
        cmRpcParseSkip(&reader, 4);
    }
    
    for (answer = 0; answer < header.answers; answer++)
    {  
        NQ_UINT16 t;                        /* next answer type */
        NQ_UINT16 dataLen;                  /* variable data length in answer */
        if (nsDnsDecodeName(&reader, NULL) == NQ_FAIL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "nsDnsDecodeName() failed");
            goto Exit;
        }
        cmRpcParseUint16(&reader, &t);
        cmRpcParseSkip(&reader, 6);
        cmRpcParseUint16(&reader, &dataLen);

        if (t == type)
        {
            switch (t)
            {
                case NS_DNS_A:
                    {
						NQ_IPADDRESS4 * p4;    /* temporary pointer */;
                        
                        if (!ip)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "NULL ip");
                            goto Exit;
                        }
                        if (maxIps > 0)
                        {
							p4 = (NQ_IPADDRESS4 *)cmBufferReaderGetPosition(&reader);
                            cmRpcParseSkip(&reader, dataLen);
                            CM_IPADDR_ASSIGN4(*ip, *p4);
                            *pNumIps += 1;
                            maxIps--;
                            ip++;
                            res = NQ_SUCCESS;
                        }
                        break;
                    }    
#ifdef UD_NQ_USETRANSPORTIPV6
                case NS_DNS_AAAA:
                    {
                        NQ_IPADDRESS6 * p6;    /* temporary pointer */

                        if (!ip)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "NULL ip");
                            goto Exit;
                        }
                        if (maxIps > 0)
                        {
                            p6 = (NQ_IPADDRESS6 *)cmBufferReaderGetPosition(&reader);
                            cmRpcParseSkip(&reader, dataLen);
                            CM_IPADDR_ASSIGN6(*ip, *p6);
                            *pNumIps += 1;
                            maxIps--;
                            ip++;
                            res = NQ_SUCCESS;
                        }
                        break;
                    }
#endif /* UD_NQ_USETRANSPORTIPV6 */
    
                case NS_DNS_CNAME:
                    {
                        NQ_CHAR str[CM_NQ_HOSTNAMESIZE + 1];    /* host size */

                        if (nsDnsDecodeName(&reader, str) == NQ_FAIL)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "nsDnsDecodeName() failed");
                            goto Exit;
                        }
                        if (name)
                        {
                        	syStrncpy(name, str, CM_NQ_HOSTNAMESIZE);
                            res = NQ_SUCCESS;
                            goto Exit;
                        }
                        LOGERR(CM_TRC_LEVEL_ERROR, "NULL name");
                        goto Exit;
                    }
                case NS_DNS_SRV:
                    {
                        NQ_CHAR str[CM_NQ_HOSTNAMESIZE + 1];    /* host size */

						cmRpcParseSkip(&reader, 6);
                        if (nsDnsDecodeName(&reader, str) == NQ_FAIL)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "nsDnsDecodeName() failed");
                            goto Exit;
                        }
						if (name && pNumIps)
                        {	
							if (*pNumIps == 0)
							{
								length = (NQ_COUNT)syStrlen(str);
								syStrcpy(name, str);
							}
							else
							{								
								syStrcpy(&name[length + 1], str);
								length += (NQ_COUNT)(syStrlen(str) + 1);
							}
							*pNumIps += 1;						
							res = NQ_SUCCESS;
                        }
                        break;
                    }
                case NS_DNS_PTR:
                    {
                        NQ_CHAR str[CM_NQ_HOSTNAMESIZE + 1];    /* host size */

                        if (nsDnsDecodeName(&reader, str) == NQ_FAIL)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "nsDnsDecodeName() failed");
                            goto Exit;
                        }
                        if (!name)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "NULL name");
                            goto Exit;
                        }

                        syStrncpy(name, str, CM_NQ_HOSTNAMESIZE);
                        res = NQ_SUCCESS;
                        goto Exit;
                    }
                default:
                    {
                        goto Exit;
                    }
            }
        }
        else
        {
            cmRpcParseSkip(&reader, dataLen);
        }
    }

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d, numIps:%d", res, pNumIps != NULL ? *pNumIps : -1);
    return res;
}

static NQ_STATUS requestByNameAndType(SYSocketHandle socket, const NQ_CHAR * name, NQ_BYTE type, void * context, const NQ_IPADDRESS * serverIp)
{
    NQ_BYTE buffer[1460];   /* output buffer */
    NQ_UINT length;         /* outgoing packet length */
    NQ_STATUS res;          /* operation result */
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d, name:%s, type:0x%x, context:%p, serverIp:%s", socket, name, type, context, cmIPDump(serverIp));

    length = dnsCreateQueryRequest(buffer, type, name);
#ifdef UD_NQ_USETRANSPORTIPV4
    if (CM_IPADDR_EQUAL(staticData->llmnrIp4, *serverIp))
    {   
        res = sySendMulticast(socket, buffer, length, serverIp, syHton16(LLMNR_PORT));
    }
    else 
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    if (CM_IPADDR_EQUAL(staticData->llmnrIp6, *serverIp))
    {   
        res = sySendToSocket(socket, buffer, length, serverIp, syHton16(LLMNR_PORT));
    }
    else
#endif /* UD_NQ_USETRANSPORTIPV6 */
    {
        res = sySendToSocket(socket, buffer, length, serverIp, syHton16(DNS_PORT));
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res > 0 ? NQ_SUCCESS : syGetLastError());
    return res > 0 ? NQ_SUCCESS : syGetLastError();
}

static NQ_STATUS requestByName(SYSocketHandle socket, const NQ_WCHAR * name, void * context, const NQ_IPADDRESS * serverIp)
{
    NQ_STATUS res;          /* operation result */
    NQ_CHAR * nameA = NULL; /* name as ACSII */
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d, name:%s, context:%p, serverIp:%s", socket, cmWDump(name), context, cmIPDump(serverIp));

    nameA = cmMemoryCloneWStringAsAscii(name);
    if (NULL == nameA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        res = NQ_ERR_NOMEM;
        goto Exit;
    }
    if (NULL == syStrchr(nameA, '.'))
    {
        NQ_CHAR * qualifiedName = (NQ_CHAR *)cmMemoryAllocate((NQ_UINT)(syStrlen(nameA) + syStrlen(staticData->dnsDomain) + 2));
        if (NULL == qualifiedName)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_NOMEM);
            res = NQ_ERR_NOMEM;
            goto Exit;
        }
        syStrcpy(qualifiedName, nameA);
        cmMemoryFree(nameA);
        if (syStrlen(staticData->dnsDomain) != 0)
        {
            syStrcat(qualifiedName, ".");
            syStrcat(qualifiedName, staticData->dnsDomain);
        }
        nameA = qualifiedName;
    }
    res = requestByNameAndType(socket, nameA, NS_DNS_A, context, serverIp);
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "requestByNameAndType() failed");
        goto Exit;
    }
    res = requestByNameAndType(socket, nameA, NS_DNS_AAAA, context, serverIp);
    res = (res == NQ_SUCCESS? 2 : res);

Exit:
    cmMemoryFree(nameA);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

static NQ_STATUS requestByNameForDC(SYSocketHandle socket, const NQ_WCHAR * name, void * context, const NQ_IPADDRESS * serverIp)
{
    NQ_CHAR * serviceName = (NQ_CHAR *)"_ldap._tcp.dc._msdcs.";
    NQ_STATUS res;             /* operation result */
    NQ_CHAR * serviceA = NULL; /* service */
    NQ_CHAR * nameA = NULL;    /* name as ACSII */
    NQ_CHAR * qualifiedName = NULL;
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d, name:%s, context:%p, serverIp:%s", socket, cmWDump(name), context, cmIPDump(serverIp));

    if (NULL != name)
    {
        nameA = cmMemoryCloneWStringAsAscii(name);
        if (NULL == nameA)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_NOMEM);
            res = NQ_ERR_NOMEM;
            goto Exit;
        }
    }

    qualifiedName = (NQ_CHAR *)cmMemoryAllocate((NQ_UINT)((nameA ? syStrlen(nameA) : 0) + syStrlen(staticData->dnsDomain) + 2));
    if (NULL == qualifiedName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        res = NQ_ERR_NOMEM;
        goto Exit;
    }

    if (NULL == nameA)
    {
        if (syStrlen(staticData->dnsDomain) != 0)
        {
            syStrcat(qualifiedName, staticData->dnsDomain);
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Empty name");
            sySetLastError(NQ_ERR_BADPATH);
            res = NQ_ERR_BADPATH;
            goto Exit;
        }
    }
    else
    {
        syStrcpy(qualifiedName, nameA);
        /*
        if (NULL == syStrchr(nameA, '.') && syStrlen(staticData->dnsDomain) != 0 && NULL != syStrchr(staticData->dnsDomain, '.'))
        {
            syStrcat(qualifiedName, staticData->dnsDomain);
        }
        */
        cmMemoryFree(nameA);
    }

    nameA = qualifiedName;
    qualifiedName = NULL;
    serviceA = (NQ_CHAR *)cmMemoryAllocate((NQ_UINT)(syStrlen(nameA) + syStrlen(serviceName) + 2));
    if (NULL == serviceA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        res = NQ_ERR_NOMEM;
        goto Exit;
    }
    syStrcpy(serviceA, serviceName);
    syStrcat(serviceA, nameA);

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "service: %s", serviceA);
    res = requestByNameAndType(socket, serviceA, NS_DNS_SRV, context, serverIp);

Exit:
    cmMemoryFree(nameA);
    cmMemoryFree(serviceA);
    cmMemoryFree(qualifiedName);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}


static NQ_STATUS responseByName(SYSocketHandle socket, NQ_IPADDRESS ** pAddressArray, NQ_INT * numIps, void ** pContext)
{
#define MAX_RESPONSE_IPS 10
    NQ_BYTE buffer[1460];       /* input buffer */
    NQ_INT count;               /* number of bytes in the incoming datagram */
    NQ_IPADDRESS srcIp;         /* source IP */
    NQ_PORT srcPort;            /* source port */
    NQ_STATUS res;              /* operation result */
    NQ_IPADDRESS result[MAX_RESPONSE_IPS];    /* resulted IPs */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d pAddressArray:%p numIps:%p pContext:%p", socket, pAddressArray, numIps, pContext);

    *numIps = MAX_RESPONSE_IPS;       /* max number of IPs */
    count = syRecvFromSocket(socket, buffer, sizeof(buffer), &srcIp, &srcPort);
    if (count <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving DNS response");
        res = (NQ_STATUS)syGetLastError();
        goto Exit;
    }

    res = dnsParseQueryResponse(buffer, NS_DNS_A, NULL, result, numIps, NULL); 
    if (NQ_SUCCESS != res)
    {
	    *numIps = MAX_RESPONSE_IPS;       /* max number of IPs */
        res = dnsParseQueryResponse(buffer, NS_DNS_AAAA, NULL, result, numIps, NULL); 
    }
    if (NQ_SUCCESS != res || *numIps == 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error parsing DNS response");
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved %d ips, 1st address: %s", *numIps, cmIPDump(&result[0]));
    
    *pAddressArray = (NQ_IPADDRESS *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * (NQ_UINT)(*numIps)));
    if (NULL == *pAddressArray)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = NQ_ERR_NOMEM;
        goto Exit;
    }
    syMemcpy(*pAddressArray, result, sizeof(NQ_IPADDRESS) * (NQ_UINT)(*numIps));
    res = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

static NQ_STATUS requestByIp(SYSocketHandle socket, const NQ_IPADDRESS * ip, void * context, const NQ_IPADDRESS * serverIp)
{
    NQ_BYTE buffer[1460];    /* output buffer */
    NQ_UINT length;          /* outgoing packet length */
    NQ_STATUS res;           /* operation result */
    NQ_CHAR * ipA;           /* IP as ACSII */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d ip:%p context:%p serverIp:%p", socket, ip, context, serverIp);

    ipA = nsDnsCreateReversedName(ip);
    if (NULL == ipA)
    {
        res = NQ_ERR_NOMEM;
        goto Exit;
    }
    length = dnsCreateQueryRequest(buffer, NS_DNS_PTR, ipA);
    cmMemoryFree(ipA);
#ifdef UD_NQ_USETRANSPORTIPV4
    if (CM_IPADDR_EQUAL(staticData->llmnrIp4, *serverIp))
    {   
        res = sySendMulticast(socket, buffer, length, serverIp, syHton16(LLMNR_PORT));
    }
    else 
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    if (CM_IPADDR_EQUAL(staticData->llmnrIp6, *serverIp))
    {   
        res = sySendToSocket(socket, buffer, length, serverIp, syHton16(LLMNR_PORT));
    }
    else
#endif /* UD_NQ_USETRANSPORTIPV6 */
    {
        res = sySendToSocket(socket, buffer, length, serverIp, syHton16(DNS_PORT));
    }
    res = ( res > 0? NQ_SUCCESS : syGetLastError() );

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}


static NQ_STATUS responseByNameForDC(SYSocketHandle socket, const NQ_WCHAR ** pName, void ** pContex)
{
    NQ_BYTE buffer[1024];                  /* input buffer */
    NQ_INT count;                          /* number of bytes in the incoming datagram */
    NQ_IPADDRESS srcIp;                    /* source IP */
    NQ_PORT srcPort;                       /* source port */
    NQ_CHAR *pDcList = NULL, *pa = NULL;   /* result in ASCII */
    NQ_WCHAR *pDcListW = NULL, *pw = NULL; /* result in WCHAR */
    NQ_INT numDcs = 0;                     /* result number of parsed DC servers */
    NQ_STATUS res = NQ_FAIL;               /* operation result */
    NQ_INT *num;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d pName:%p pContex:%p", socket, pName, pContex);

    count = syRecvFromSocket(socket, buffer, sizeof(buffer), &srcIp, &srcPort);
    if (count <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving DNS response");
        res = (NQ_STATUS)syGetLastError();
        goto Exit;
    }

    /* allocate max space for DNS names as max UDP DNS packet length */
    pDcList = (NQ_CHAR *)cmMemoryAllocate(1024);
    if (NULL == pDcList)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = NQ_ERR_NOMEM;
        goto Exit;
    }
	pDcList[0] = '\0';
    res = dnsParseQueryResponse(buffer, NS_DNS_SRV, NULL, 0, &numDcs, pDcList);  
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error parsing DNS response");
        goto Exit;
    }

    pDcListW = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)numDcs * (NQ_UINT)sizeof(NQ_WCHAR) * (CM_DNS_NAMELEN + 1));
    if (NULL == pDcListW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = NQ_ERR_NOMEM;
        goto Exit;
    }

    pDcListW[0] = cmWChar('\0');
    for (pw = pDcListW, pa = pDcList, count = 0; count < numDcs; count++)
    {
        NQ_UINT lenW = 0;
        NQ_WCHAR *p = cmMemoryCloneAString(pa);
        
        if (NULL != p)
        {
            lenW = cmWStrlen(p);
            cmWStrcpy(pw, p);
            pw[lenW] = cmWChar('\0');
            cmMemoryFree(p);
        }
        pw += lenW + 1;
        pa += syStrlen(pa) + 1;        
    }
    *pName = pDcListW;
    *pContex = num = (NQ_INT *)cmMemoryAllocate(sizeof(numDcs));
    if (NULL == num)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = NQ_ERR_NOMEM;
        goto Exit;
    }
    *num = numDcs;
    res = NQ_SUCCESS;

Exit:
    cmMemoryFree(pDcList);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

static NQ_STATUS responseByIp(SYSocketHandle socket, const NQ_WCHAR ** pName, void ** pContex)
{
    NQ_BYTE buffer[1024];    /* input buffer */
    NQ_INT count;            /* number of bytes in the incoming datagram */
    NQ_IPADDRESS srcIp;      /* source IP */
    NQ_PORT srcPort;         /* source port */
    NQ_CHAR * pNameA = NULL; /* result in ASCII */
    NQ_STATUS res;           /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d pName:%p pContex:%p", socket, pName, pContex);

    count = syRecvFromSocket(socket, buffer, sizeof(buffer), &srcIp, &srcPort);
    if (count <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving DNS response");
        res = (NQ_STATUS)syGetLastError();
        goto Exit;
    }

    pNameA = (NQ_CHAR *)cmMemoryAllocate(CM_DNS_NAMELEN + 1);
    if (NULL == pNameA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = NQ_ERR_NOMEM;
        goto Exit;
    }
    res = dnsParseQueryResponse(buffer, NS_DNS_PTR, NULL, 0, NULL, pNameA); 
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error parsing DNS response");
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved name: %s", pNameA);

    *pName = cmMemoryCloneAString(pNameA);
    res = ( NULL == *pName? NQ_ERR_NOMEM : NQ_SUCCESS );

Exit:
    cmMemoryFree(pNameA);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

static void parseServerList(NQ_WCHAR * list)
{
    CMResolverMethodDescriptor method;                      /* next method descriptor */
    CMResolverMethodDescriptor methodDC;                    /* next method descriptor */
    NQ_WCHAR * curServer;                                   /* pointer to the current server IP */
    NQ_WCHAR * nextServer;                                  /* pointer to the next server IP */
    NQ_CHAR aServer[CM_IPADDR_MAXLEN];                      /* the same in ASCII */

    method.type = NQ_RESOLVER_DNS;
    method.isMulticast = FALSE;  	/* unicast */
    method.activationPriority = 2;
    method.timeout.low = 1000; 			/* milliseconds */
    method.timeout.high = 0; 			/* milliseconds */
    method.waitAnyway = TRUE;
    method.requestByName = requestByName;
    method.responseByName = responseByName;
    method.requestByIp = requestByIp;
    method.responseByIp = responseByIp;

    methodDC.type = NQ_RESOLVER_DNS_DC;
    methodDC.isMulticast = FALSE;  	/* unicast */
    methodDC.activationPriority = 2;
    methodDC.timeout.low = 1000;		/* milliseconds */
    methodDC.timeout.high = 0; 			/* milliseconds */
    methodDC.waitAnyway = FALSE;
    methodDC.requestByName = requestByNameForDC;
    methodDC.responseByName = NULL;
    methodDC.requestByIp = NULL;
    methodDC.responseByIp = responseByNameForDC;

    syMutexTake(&staticData->guard);
    /* parse servers string */
    for (curServer = list, staticData->numServers = 0;
        staticData->numServers < sizeof(staticData->dnsServers) / sizeof(staticData->dnsServers[0]);
        curServer = nextServer + 1
        )
    {
        NQ_STATUS res;                      /* operation status */

        nextServer = cmWStrchr(curServer, cmWChar(';'));
        if (NULL != nextServer)
        {
            *nextServer = cmWChar('\0');
        }
		if (cmWStrlen(curServer) < CM_IPADDR_MAXLEN)
		{
			cmUnicodeToAnsiN(aServer, curServer, CM_IPADDR_MAXLEN * 2);
			res = cmAsciiToIp(aServer, &staticData->dnsServers[staticData->numServers]);
			if (NQ_SUCCESS == res)
			{
				/* register DNS with Resolver */
				cmResolverRemoveMethod(&method, &staticData->dnsServers[staticData->numServers]);
				cmResolverRegisterMethod(&method, &staticData->dnsServers[staticData->numServers]);
                /* register DNS DC with Resolver */
                cmResolverRemoveMethod(&methodDC, &staticData->dnsServers[staticData->numServers]);
				cmResolverRegisterMethod(&methodDC, &staticData->dnsServers[staticData->numServers]);

				staticData->numServers++;
			}
		}

        if (NULL == nextServer)
            break;
    }
    syMutexGive(&staticData->guard);
}

static void dnsGetServers(void)
{
    NQ_WCHAR * serverList = NULL;                          /* buffer for DNS servers string */
    NQ_WCHAR * serverListW = NULL;                          /* buffer for DNS servers string in Unicode */
    NQ_WCHAR * domain = NULL;                              /* buffer for server name */
    CMResolverMethodDescriptor method;                      /* next method descriptor */

    if (staticData->isNewServerSet)
        goto Exit;

    serverList = (NQ_WCHAR *)cmMemoryAllocate(UD_DNS_SERVERSTRINGSIZE * sizeof(NQ_WCHAR));
    domain = (NQ_WCHAR *)cmMemoryAllocate((CM_NQ_HOSTNAMESIZE + 1) * sizeof(NQ_WCHAR));

    if (NULL == serverList || NULL == domain)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    udGetDnsParams(domain, serverList);
    cmUnicodeToAnsi(staticData->dnsDomain, domain);

    serverListW = cmMemoryCloneWString(serverList);

    if (NULL == serverListW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    parseServerList(serverListW);

    method.type = NQ_RESOLVER_DNS;
    method.isMulticast = TRUE;
    method.activationPriority = 4;
    method.timeout.low = 1000; /* milliseconds */
    method.timeout.high = 0;   /* milliseconds */
    method.waitAnyway = TRUE;
    method.requestByName = requestByName;
    method.responseByName = responseByName;
    method.requestByIp = requestByIp;
    method.responseByIp = responseByIp;
#ifdef UD_NQ_USETRANSPORTIPV4
    cmAsciiToIp((NQ_CHAR *)"224.0.0.252", &staticData->llmnrIp4);
    cmResolverRemoveMethod(&method, &staticData->llmnrIp4);
    cmResolverRegisterMethod(&method, &staticData->llmnrIp4);
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    cmAsciiToIp("FF02:0:0:0:0:0:1:3", &staticData->llmnrIp6);
    cmResolverRemoveMethod(&method, &staticData->llmnrIp6);
    cmResolverRegisterMethod(&method, &staticData->llmnrIp6);
#endif /* UD_NQ_USETRANSPORTIPV6 */

Exit:
    cmMemoryFree(serverListW);  /* takes care of NULL */
    cmMemoryFree(domain);      /* take care of NULL */
    cmMemoryFree(serverList);  /* takes care of NULL */
}

/* send and receive DNS datagram */
static NQ_INT dnsDatagramExchange(
    NQ_IPADDRESS * serverIp,
    NQ_BYTE * buffer,
    NQ_COUNT dataLength,
    NQ_COUNT bufferSize
    )
{
    SYSocketHandle socket;      /* socket */
    SYSocketSet set;            /* socket set */
    NQ_IPADDRESS tip;           /* dummy */
    NQ_PORT tport;              /* dummy */
    NQ_INT res;                 /* function result */
    NQ_INT result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "serverIp:%p buffer:%p dataLength:%d bufferSize:%d", serverIp, buffer, dataLength, bufferSize);

    socket = syCreateSocket(FALSE, CM_IPADDR_VERSION(*serverIp));
    if (!syIsValidSocket(socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error creating DNS socket");
        goto Exit;
    }

    if (sySendToSocket(socket, buffer, dataLength, serverIp, syHton16(DNS_PORT)) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending DNS request");
        goto Error;
    }

    syClearSocketSet(&set);
    syAddSocketToSet(socket, &set);

    switch (sySelectSocket(&set, DNS_TIMEOUT))
    {
    case 0:  /* timeout */
        LOGERR(CM_TRC_LEVEL_ERROR, "DNS Timeout occured");
        goto Error;
    case -1: /* error or exit */
        LOGERR(CM_TRC_LEVEL_ERROR, "DNS Error occured");
        goto Error;
    };

    res = syRecvFromSocket(socket, buffer, bufferSize, &tip, &tport);
    if (res <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "DNS Error occured");
        goto Error;
	};
    result = res;

Error:
    syCloseSocket(socket);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

/* create a unique TKEY name */
#ifndef UD_CM_DONOTREGISTERHOSTNAMEDNS
static void createTkeyName(NQ_CHAR * name)
{
    NQ_IPADDRESS ip;        /* show id as IP */
    NQ_IPADDRESS4 ip4;      /* show id as IP */

    /*  Tkey name has the format:
            vs-nq-<n>-<time>
        <n> is ID number modulo 10.
        <time> is current Unix time in secs, formatted as IP address.
        Why IP address? just for fun and since 
        we have an appopriate function in hand */
    syMutexTake(&staticData->guard);
    syStrcpy (name, "vs-nq-x-");
    name[6] = (NQ_CHAR)('0' + (staticData->id%10));
    ip4 = (NQ_IPADDRESS4)syGetTimeInSec();
    CM_IPADDR_ASSIGN4(ip, ip4);
    cmIpToAscii(name + 8, &ip);
    syMutexGive(&staticData->guard);
}

static NQ_STATUS dnsQueryTkey(void * context, const CMBlob * in, CMBlob * out)
{
    NQ_BYTE buffer[1460];               /* for header + queries */
    CMRpcPacketDescriptor descr;        /* packer and parser */
    DnsHeader header;                   /* header */
    NQ_BYTE *pTemp;                     /* pointer in packet */
    NQ_STATUS status;                   /* operation result */
    SYSocketSet set;                    /* socket set */
    NQ_COUNT count;                     /* receive count */
    NQ_BYTE tempByte;                   /* for parsing byte values */
    NQ_UINT16 temp16;                   /* for parsing two-byte values */
    TkeyContext * pTkey;                /* casted pointer */
    NQ_STATUS result = NQ_FAIL;         /* return value */
    const NQ_BYTE queryData[] = {0, 0xf9, 0, 0x01};
    const NQ_BYTE additionalData[] = {0, 0xf9, 0, 0xff, 0, 0, 0, 0};
    const NQ_BYTE other[] = {0, 0};
#define ALGORITHM_NAME "gss-tsig"
#define TKEY_EXTRALEN 26
#define SECS_IN_DAY (60 * 60 * 24)
#define MODE_GSSAPI 3

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "context:%p in:%p out:%p", context, in, out);

    pTkey = (TkeyContext *)context;
    /* compose and transmit DNS header + queries */
    cmRpcSetDescriptor(&descr, buffer, TRUE);  /* nbo */
    cmRpcPackSkip(&descr, sizeof(NQ_UINT16));  /* skip packet length */
    syMutexTake(&staticData->guard);
    header.id = ++staticData->id;
    syMutexGive(&staticData->guard);
    header.flags1 = 0;
    header.flags2 = 0;
    header.questions = 1;
    header.answers = 0;
    header.authority = 0;
    header.additional = 1;
    nsWriteDnsHeader(&descr, &header);
    writeBlock(&descr, pTkey->name, queryData, sizeof(queryData));
    writeBlock(&descr, pTkey->name, additionalData, sizeof(additionalData));
    cmRpcPackUint16(&descr, (NQ_UINT16)(in->len + TKEY_EXTRALEN));           /* data length */
    cmRpcPackByte(&descr, sizeof(ALGORITHM_NAME) - 1);          /* algorithm as size-prefixed null-terminated */
    cmRpcPackAscii(&descr, ALGORITHM_NAME, CM_RP_NULLTERM);     /* algorithm */
    cmRpcPackUint32(&descr, (NQ_UINT32)syGetTimeInSec());                       /* signature creation */
    cmRpcPackUint32(&descr, (NQ_UINT32)(syGetTimeInSec() + SECS_IN_DAY));         /* signature expiration */
    cmRpcPackUint16(&descr, MODE_GSSAPI);                       /* mode */
    cmRpcPackUint16(&descr, 0);                                 /* no error */
    cmRpcPackUint16(&descr, (NQ_UINT16)in->len);                           /* key size */
    pTemp = descr.current;
    descr.current = buffer;
    cmRpcPackUint16(&descr, (NQ_UINT16)((pTemp - descr.current - 2) + (NQ_UINT16)in->len + (NQ_UINT16)sizeof(other)));   /* packet length */
    status = sySendSocket(pTkey->socket, buffer, (NQ_UINT)(pTemp - buffer));
    if (NQ_FAIL == status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to transmit TKEY query");
        result = NQ_SUCCESS;
        goto Exit;
    }

    /* send TKEY payload */
    status = sySendSocket(pTkey->socket, in->data, (NQ_UINT)in->len);
    if (NQ_FAIL == status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to transmit TKEY query");
        goto Exit;
    }

    /* send "other" */
    status = sySendSocket(pTkey->socket, other, sizeof(other));
    if (NQ_FAIL == status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to transmit TKEY query");
        goto Exit;
    }

    /* receive response */
    syClearSocketSet(&set);
    syAddSocketToSet(pTkey->socket, &set);
    switch (sySelectSocket(&set, DNS_TIMEOUT))
    {
        case 0:  /* timeout */
            LOGMSG(CM_TRC_LEVEL_ERROR, "DNS Timeout occured for TKey request");
            goto Exit;

        case -1: /* error or exit */
            LOGERR(CM_TRC_LEVEL_ERROR, "DNS Error occured");
            goto Exit;
    };
    count = (NQ_COUNT)syRecvSocket(pTkey->socket, buffer, sizeof(buffer));
    if (count <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving DNS response");
        goto Exit;
    }

    /* skip header and queries */
    cmRpcSetDescriptor(&descr, buffer, TRUE);       /* nbo */
    cmRpcParseSkip(&descr, sizeof(NQ_UINT16));      /* packet length */
    nsReadDnsHeader(&descr, &header);
    if ((header.flags2 & 0xF) != 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error DNS response 0x%x", header.flags2);
        goto Exit;
    }
    
    if (nsDnsDecodeName(&descr, NULL) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "nsDnsDecodeName() failed");
        goto Exit;
    }
    cmRpcParseSkip(&descr, 4);

    /* parse answer */
    if (nsDnsDecodeName(&descr, NULL) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "nsDnsDecodeName() failed");
        goto Exit;
    }
    cmRpcParseSkip(&descr, 10);            /* type, class, TTL, data length */
    cmRpcParseByte(&descr, &tempByte);     /* algorithm name length */
    cmRpcParseSkip(&descr, (NQ_UINT32)(tempByte + 1));  /* algorithm name */
    cmRpcParseSkip(&descr, 10);            /* times, mode */
    cmRpcParseUint16(&descr, &temp16);     /* error */
    if (0 != temp16)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Server failed the request");
        goto Exit;
    }
    cmRpcParseUint16(&descr, &temp16);     /* key size */
    out->data = (NQ_BYTE *)cmMemoryAllocate(temp16);
    if (NULL == out->data)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    out->len = temp16;
    cmRpcParseBytes(&descr, out->data, out->len);     /* key */
    cmRpcParseSkip(&descr, 2);                        /* other size */

    /* parse additional record */
    count = count - (NQ_COUNT)(descr.current - buffer);   /* tkey length */
    pTkey->tkey.data = (NQ_BYTE *)cmMemoryAllocate(count);
    if (NULL == pTkey->tkey.data)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }
    pTkey->tkey.len = count;
    cmRpcParseBytes(&descr, pTkey->tkey.data, pTkey->tkey.len);     /* tkey */
    pTkey->originalIdOffset = (NQ_INT)(pTkey->tkey.len - 6);
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

static NQ_STATUS dnsStartTkey(TkeyContext * pTkey, const NQ_IPADDRESS * serverIp)
{
    NQ_INT ipVersion;               /* v4 or v6 */
    NQ_STATUS status = NQ_FAIL;     /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pTkey:%p serverIp:%p", pTkey, serverIp);

    pTkey->sessionKey.data = NULL;
    pTkey->macKey.data = NULL;
    pTkey->ip = serverIp;
    pTkey->tkey.data = NULL;

    /* create and connect socket */
    ipVersion = CM_IPADDR_VERSION(*serverIp);
    pTkey->socket = syCreateSocket(TRUE, (NQ_UINT)ipVersion);
    if (!syIsValidSocket(pTkey->socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create TCP socket");
        goto Exit;
    }
    status = syConnectSocket(pTkey->socket, serverIp, syHton16(DNS_PORT));
    if (NQ_SUCCESS != status)
    {
        syCloseSocket(pTkey->socket);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect to DNS server over TCP");
        goto Exit;
    }
    createTkeyName(pTkey->name);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

static void dnsFreeTkeyContext(TkeyContext * pTkey)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pTkey:%p", pTkey);

    cmMemoryFreeBlob(&pTkey->tkey);
    cmMemoryFreeBlob(&pTkey->sessionKey);
    cmMemoryFreeBlob(&pTkey->macKey);

    if (syIsSocketAlive(pTkey->socket))
    {
        syCloseSocket(pTkey->socket);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return;
}

#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */
#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

static NQ_STATUS dnsQueryService(
    const NQ_CHAR * service,
    NQ_CHAR * host
    )
{
    NQ_COUNT i;                     /* index in DNS servers */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "service:%p host:%p", service, host);

    /* try request with each of the DNS servers until one of them suceeds */
    dnsGetServers();

    for (i = 0; i < staticData->numServers; i++)
    {
        NQ_BYTE buffer[1460];           /* send/receive buffer */
        DnsHeader header;               /* header */
        CMRpcPacketDescriptor descr;    /* packet writer */
        NQ_INT res;                     /* operation result */
        const NQ_BYTE query[] = {0, NS_DNS_SRV, 0, 0x01};
        NQ_INT answer;                  /* current answer */

        cmRpcSetDescriptor(&descr, buffer, TRUE);
        syMutexTake(&staticData->guard);
        header.id = ++staticData->id;
        syMutexGive(&staticData->guard);
        header.flags1 = DNS_QUERY;
        header.flags2 = 0;
        header.questions = 1;
        header.answers = 0;
        header.authority = 0;
        header.additional = 0;
        nsWriteDnsHeader(&descr, &header);
        writeBlock(&descr, service, query, sizeof(query));

        res = dnsDatagramExchange(&staticData->dnsServers[i], buffer, (NQ_COUNT)(descr.current - descr.origin), sizeof(buffer));
        if (res <= 0)
        {
            continue;
        }

        cmRpcSetDescriptor(&descr, buffer, TRUE);
        nsReadDnsHeader(&descr, &header);
        if (header.answers < 1 || DNS_REPLY_CODE_NO_SUCH_NAME == (header.flags2 & DNS_REPLY_CODE))
        {
            continue;
        }
        if (nsDnsDecodeName(&descr, NULL) == NQ_FAIL)
        {
            continue;
        }
        cmRpcParseSkip(&descr, 4);

        for (answer = 0; answer < header.answers; answer++)
        {  
            NQ_UINT16 t;                          /* next answer type */
            NQ_UINT16 dataLen;                  /* variable data length in answer */

            if (nsDnsDecodeName(&descr, NULL) == NQ_FAIL)
            {
                break;
            }
            cmRpcParseUint16(&descr, &t);
            cmRpcParseSkip(&descr, 6);
            cmRpcParseUint16(&descr, &dataLen);
            switch (t)
            {
                case NS_DNS_CNAME:
                case NS_DNS_SRV:
                case NS_DNS_PTR:
                    {
                        NQ_CHAR str[CM_NQ_HOSTNAMESIZE + 1];    /* redirection target */

                        cmRpcParseSkip(&descr, 6);
                        if (nsDnsDecodeName(&descr, str) == NQ_FAIL)
                        {
                            goto Exit;
                        }
                        syStrncpy(host, str, CM_NQ_HOSTNAMESIZE);
                        result = NQ_SUCCESS;
                        break;
                    }
                default:
                    {
                        goto Exit;
                    }
            }
        }
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

#ifndef UD_CM_DONOTREGISTERHOSTNAMEDNS
/* update on one server with optional TKEY */
static NQ_STATUS dnsUpdateOneServer(
    NQ_UINT16 type,
    NQ_IPADDRESS * serverIp,
    NQ_CHAR * host,
    NQ_IPADDRESS *hostIPs,
    NQ_UINT16 numHostIPs,
    const TkeyContext * pTkey
    )
{
    NQ_BYTE buffer[1460];   /* send and receive buffer */
    NQ_UINT length;         /* data length */
    const NQ_BYTE zone[]    = {0, NS_DNS_SOA,   0, 0x01};
    const NQ_BYTE prereq[]  = {0, NS_DNS_CNAME, 0, 0xfe, 0, 0, 0, 0, 0, 0};
    NQ_BYTE update1[] = {0, 0,            0, 0xff, 0, 0, 0, 0, 0, 0};
    NQ_BYTE update2[] = {0, 0,            0, 0x01, 0, 0, 0x03, 0x84};
    DnsHeader header;                       /* header */
    NQ_CHAR * domain;                       /* pointer to domain inside FQN */
    NQ_COUNT i;                             /* just a counter */
    CMRpcPacketDescriptor descr;           /* packet reader/writer */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "type:%u serverIp:%p host:%p hostIPs:%p numHostIPs:%u pTkey:%p", type, serverIp, host, hostIPs, numHostIPs, pTkey);

    /* compose request */
    cmRpcSetDescriptor(&descr, buffer, TRUE);
    syMutexTake(&staticData->guard);
    header.id = ++staticData->id;
    syMutexGive(&staticData->guard);
    header.flags1 = DNS_UPDATE;
    header.flags2 = 0;
    header.questions = 1;  
    header.answers   = 1;          /* zones and prerequisites */
    header.authority = (NQ_UINT16)(numHostIPs + 1);
    header.additional = NULL == pTkey? 0 : 1;
    nsWriteDnsHeader(&descr, &header);
    domain = syStrchr(host, '.');
    if (NULL == domain)
        goto Exit;

    domain++;
    writeBlock(&descr, domain, zone, sizeof(zone));
    writeBlock(&descr, host, prereq, sizeof(prereq));
    update1[1] = (NQ_BYTE)type;
    writeBlock(&descr, host, update1, sizeof(update1)); /* class ANY */
    if (NULL != hostIPs)
    {
        for (i = 0; i < numHostIPs; i++)
        {
            update2[1] = (NQ_BYTE)type;
            writeBlock(&descr, host, update2, sizeof(update2)); /* class IN */
            cmRpcPackByte(&descr, 0);
            cmRpcPackByte(&descr, CM_IPADDR_SIZE(hostIPs[i]));    /* data length */            
            switch (type)
            {
#ifdef UD_NQ_USETRANSPORTIPV4
                case NS_DNS_A:
                    {
                        NQ_IPADDRESS4 ip4 = CM_IPADDR_GET4(hostIPs[i]);
                        cmRpcPackUint32(&descr, syNtoh32(ip4));
                        break;
                    }
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
                case NS_DNS_AAAA:
                    cmRpcPackBytes(&descr, (NQ_BYTE *)CM_IPADDR_GET6(hostIPs[i]), CM_IPADDR_SIZE(hostIPs[i]));
                    break;
#endif /* UD_NQ_USETRANSPORTIPV6 */

                default:
                    goto Exit;
            }
        }
    }
    if (NULL != pTkey)
    {
        setTkeyOriginalId(pTkey, header.id); 
        cmRpcPackBytes(&descr, pTkey->tkey.data, pTkey->tkey.len);       /* TKEY record */
    }
    length = (NQ_UINT)(descr.current - descr.origin);

    /* send request and receive response */
    length = (NQ_UINT)dnsDatagramExchange(serverIp, buffer, length, sizeof(buffer));
    if (length <= 0)
    {
        goto Exit;
    }

    cmRpcSetDescriptor(&descr, buffer, TRUE);
    nsReadDnsHeader(&descr, &header);
    if (DNS_REPLY_CODE_REFUSED == (header.flags2 & DNS_REPLY_CODE))
    {
        /* force secure exchange */ 
        result = DNS_REPLY_CODE_REFUSED;
        goto Exit;
    }
    if (0 != (header.flags2 & DNS_REPLY_CODE))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "flags2:%d", header.flags2);
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */

/* perform on all servers, forcing TKey query if needed */ 
static NQ_STATUS dnsUpdate(
    NQ_UINT16 type,
    NQ_IPADDRESS *hostIPs,
    NQ_UINT16 numHostIPs
    )
{
    NQ_STATUS result = NQ_FAIL;             /* return value */
#ifndef UD_CM_DONOTREGISTERHOSTNAMEDNS
    NQ_COUNT i;                             /* index in DNS servers */
    NQ_CHAR host[CM_NQ_HOSTNAMESIZE + 1];   /* self host name */
    NQ_STATUS res = NQ_FAIL;                /* update status */
    NQ_STATUS status = NQ_FAIL;             /* operation result */
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */
#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)
    AMCredentialsW * pCredentials = NULL;  /* user credentials */
    const NQ_WCHAR * hostW = NULL;         /* host name in Unicode */
#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "type:%d hostIPs:%p numHostIPs:%u", type, hostIPs, numHostIPs);

#ifdef UD_CM_DONOTREGISTERHOSTNAMEDNS
    result = NQ_SUCCESS;
    goto Exit1;
#else /* UD_CM_DONOTREGISTERHOSTNAMEDNS */

    dnsNormalizeName(cmGetFullHostName(), host);

    /* try request with each of the DNS servers until one of them succeeds */
    dnsGetServers();

    for (i = 0; i < staticData->numServers; i++)
    {
        status = dnsUpdateOneServer(type, &staticData->dnsServers[i], host, hostIPs, numHostIPs, NULL);
#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)
        if (DNS_REPLY_CODE_REFUSED == status)    /* secure exchange required */
        {
            TkeyContext context;            /* secure authentication exchange */
            pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentials));
            hostW = cmMemoryCloneAString(host);
            if (NULL == pCredentials || NULL == hostW)
            {
		        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                sySetLastError(NQ_ERR_NOMEM);
		        goto Exit;
            }
    	    if (!udGetCredentials(hostW, pCredentials->user, pCredentials->password, pCredentials->domain.name))
	        {
		        LOGERR(CM_TRC_LEVEL_ERROR, "udGetCredentials break by user");
		        sySetLastError(NQ_ERR_BADPARAM);
		        goto Exit;
	        }

            cmWStrupr(pCredentials->domain.name);

            status = dnsStartTkey(&context, &staticData->dnsServers[i]);
            if (NQ_SUCCESS != status)
            {
                goto Exit;
            }
    
            status = amSpnegoClientLogon(&context, NULL, pCredentials, FALSE, NULL, &context.sessionKey, &context.macKey, dnsQueryTkey);
            if (AM_SPNEGO_SUCCESS == status)
            {
                status = dnsUpdateOneServer(type, &staticData->dnsServers[i], host, hostIPs, numHostIPs, &context);
            }
            dnsFreeTkeyContext(&context);

            cmMemoryFree(hostW);
            hostW = NULL;

            cmMemoryFree(pCredentials);
            pCredentials = NULL;
        }
#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */
        if (NQ_SUCCESS == status)
            res = NQ_SUCCESS;
    }
    staticData->isRegistered = TRUE;
    result = res;
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)
#ifndef UD_CM_DONOTREGISTERHOSTNAMEDNS
Exit:
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */
    cmMemoryFree(hostW);
    cmMemoryFree(pCredentials);
#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */
#ifdef UD_CM_DONOTREGISTERHOSTNAMEDNS
Exit1:
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/* -- API functions -- */

NQ_STATUS nsDnsInit(void)
{
    NQ_STATUS result = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate DNS data");
        result = NQ_FAIL;
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    syMutexCreate(&staticData->guard);
    staticData->id = 1;
    staticData->isRegistered = FALSE;
    staticData->isNewServerSet = FALSE;
    dnsGetServers();    /* to have domain name */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

void nsDnsExit(void)
{
#ifdef UD_NQ_USETRANSPORTIPV4
    nsDnsClearTargetAddress(NS_DNS_A);
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    nsDnsClearTargetAddress(NS_DNS_AAAA);
#endif /* UD_NQ_USETRANSPORTIPV6 */
	syMutexDelete(&staticData->guard);
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

NQ_STATUS nsDnsGetHostNameByService(const NQ_CHAR * service, NQ_CHAR * name)
{
    NQ_STATUS result = NQ_FAIL;
    NQ_CHAR   tmp[CM_NQ_HOSTNAMESIZE + 1];

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "service:%p name:%p", service, name);

    if (NULL == name || NULL == service || 0 == syStrlen(service))
    {
        goto Exit;
    }

    dnsNormalizeName(service, tmp);
    result = dnsQueryService(tmp, name);


Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Updates the DNS with all addresses of the target
 *--------------------------------------------------------------------
 * PARAMS:  type - the address type: NS_DNS_A or NS_DNS_AAAA
 *
 * RETURNS: NQ_SUCCESS on success
 *
 * NOTE:
 *====================================================================
 */
NQ_STATUS nsDnsSetTargetAddresses(void)
{
    NQ_IPADDRESS hostIps[UD_NS_MAXADAPTERS];    /* array of host IPs of just one type */
    NQ_COUNT numHostIps = 0;                    /* number of host IPs of just one type */
    NQ_STATUS status = NQ_FAIL;                 /* function result */
    const CMSelfIp * nextIp = NULL;             /* next self IP address */ 

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (*(cmNetBiosGetHostNameInfo()->name) == '\0')  
	{
		status = NQ_SUCCESS;
		goto Exit;
	}

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTNETBIOS)
    cmSelfipIterate();
    for (numHostIps = 0; ;)
    {
        nextIp = cmSelfipNext();
        if (NULL == nextIp)
            break;
        if (CM_IPADDR_IPV4 == CM_IPADDR_VERSION(nextIp->ip))
            hostIps[numHostIps++] = nextIp->ip;
    }
    cmSelfipTerminate();
    if (numHostIps > 0)
        status = dnsUpdate(NS_DNS_A, hostIps, (NQ_UINT16)numHostIps);

#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTNETBIOS) */

#if defined(UD_NQ_USETRANSPORTIPV6)
    cmSelfipIterate();
    for (numHostIps = 0; ;)
    {
        nextIp = cmSelfipNext();
        if (NULL == nextIp)
            break;
        if (CM_IPADDR_IPV6 == CM_IPADDR_VERSION(nextIp->ip))
            hostIps[numHostIps++] = nextIp->ip;
    }
    cmSelfipTerminate();
    if (numHostIps > 0)
        status = dnsUpdate(NS_DNS_AAAA, hostIps, (NQ_UINT16)numHostIps);
#endif /* defined(UD_NQ_USETRANSPORTIPV6) */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

void cmDnsSetServersA(const NQ_CHAR * servers)
{
    const NQ_WCHAR * serversW;      /* unicode copy */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "servers:%p", servers);

    if (NULL == servers)
    {
    	cmDnsSetServersW(NULL);
        goto Exit;
    }

    serversW = cmMemoryCloneAString(servers);
    if (NULL != serversW)
        cmDnsSetServersW(serversW);
    cmMemoryFree(serversW);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void cmDnsSetServersW(const NQ_WCHAR * servers)
{
    NQ_INT idx;                             /* index in servers */
    CMResolverMethodDescriptor descriptor;  /* method descriptor */
    NQ_WCHAR * aCopy;                       /* server list copy */

    syMutexTake(&staticData->guard);
    /* remove per DNS server methods */
    descriptor.type = NQ_RESOLVER_DNS;  /* only type and multicast flag are required */
    descriptor.isMulticast = FALSE;
    staticData->isNewServerSet = TRUE;
    for (idx = 0; idx < (NQ_INT)staticData->numServers; idx++)
    {
        cmResolverRemoveMethod(&descriptor, &staticData->dnsServers[idx]);
    }
    staticData->numServers = 0;
    if (NULL != servers && 0 != syWStrlen(servers))
    {
        aCopy = cmMemoryCloneWString(servers);
        if (NULL != aCopy)
        {
            parseServerList(aCopy);
            cmMemoryFree(aCopy);
        }

    }
    syMutexGive(&staticData->guard);
}

/*
 *====================================================================
 * PURPOSE: Clears from the DNS address of the target
 *--------------------------------------------------------------------
 * PARAMS:  type - the address type: NS_DNS_A or NS_DNS_AAAA
 *
 * RETURNS: NQ_SUCCESS on success
 *
 * NOTE:
 *====================================================================
 */
NQ_STATUS nsDnsClearTargetAddress(NQ_BYTE type)
{
    if (staticData->isRegistered)
    {
        dnsUpdate(NS_DNS_A, NULL, 0);
        dnsUpdate(NS_DNS_AAAA, NULL, 0);
    }
    return NQ_SUCCESS;
}

NQ_STATUS cmDnsSetDomainA(
		const NQ_CHAR * domainName
		)
{
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domainName:%s", domainName ? domainName : "");

	if (domainName == NULL || syStrlen(domainName) > (CM_NQ_HOSTNAMESIZE +1) || syStrlen(domainName) < 1 )
	{
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal domainName");
		goto Exit;
	}

	syMutexTake(&staticData->guard);

	syStrncpy(staticData->dnsDomain , domainName, CM_NQ_HOSTNAMESIZE);
	staticData->isNewServerSet = TRUE;

	syMutexGive(&staticData->guard);

    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
	return result;
}


NQ_STATUS cmDnsSetDomainW(
		const NQ_WCHAR * domainName
		)
{
    NQ_STATUS result = NQ_FAIL;
	NQ_CHAR   domainNameA[CM_NQ_HOSTNAMESIZE + 1];

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domainName:%s", cmWDump(domainName));

	if (domainName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "NULL domainName");
        goto Exit;
    }

	cmUnicodeToAnsi((NQ_CHAR *)&domainNameA , domainName);

    result = cmDnsSetDomainA((const NQ_CHAR *)&domainNameA);


Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
   return result;
}

#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */
