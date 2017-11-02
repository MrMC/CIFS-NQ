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

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)

#define DNS_PORT       53       /* The UDP port used for DNS queries */
#define LLMNR_PORT     5355     /* The UDP port used for LLMNR queries */
#define DNS_TIMEOUT    4        /* Timeout for DNS requests in seconds */
#define DNS_QUERY      0x01
#define DNS_UPDATE     0x28
#define NS_DNS_CNAME   0x05
#define NS_DNS_SOA     0x06
#define DNS_REPLY_CODE 0xf
#define DNS_REPLY_CODE_NO_SUCH_NAME 0x3
#define DNS_REPLY_CODE_REFUSED 0x5
#define DNS_UPDATE_RESPONSE         0xa8

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

typedef struct
{
    NQ_UINT16 id;
    NQ_BYTE flags1;
    NQ_BYTE flags2;
    NQ_UINT16 questions;
    NQ_UINT16 answers;
    NQ_UINT16 authority;
    NQ_UINT16 additional;
}
DnsHeader;

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
static void writeHeader(CMRpcPacketDescriptor * writer, const DnsHeader * pHeader)
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
static void readHeader(CMRpcPacketDescriptor * reader, DnsHeader * pHeader)
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
static void dnsEncodeName(CMRpcPacketDescriptor * writer, const NQ_CHAR *name)
{
    NQ_CHAR *s;     /* pointer in string */
    NQ_UINT length; /* next segment length */

    do
    {
        s = syStrchr(name, '.');
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
static NQ_STATUS dnsDecodeName(CMRpcPacketDescriptor * reader, NQ_CHAR * name)
{
    NQ_BYTE * p;        /* pointer in DNS string */
    NQ_BOOL jump;       /* jump indicator */
    NQ_UINT length;     /* segment length */

    if (name)
        *name = '\0';

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
            syStrncat((NQ_CHAR*)name, (NQ_CHAR*)p, length);
        p += length;
        if (name && *p)
            syStrcat((NQ_CHAR*)name, ".");
        if (!jump)
            cmBufferReaderSkip(reader, length + 1);
    }

    if (!jump)
        cmBufferReaderSkip(reader, 1);
    return NQ_SUCCESS;
}

/* add domain name to a name if it is not FQ */
static void dnsNormalizeName(const NQ_CHAR * host, NQ_CHAR *tmp)
{
    NQ_IPADDRESS ip;    /* dummy */

    if (NQ_SUCCESS == cmAsciiToIp((NQ_CHAR *)host + 2, &ip))
    {
        return;
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
}

/* create a reverse-order ASCII representation of IP address
   a new string is allocated and the caller should free it
*/
static NQ_CHAR * createReversedName(const NQ_IPADDRESS * ip)
{
    NQ_CHAR * buffer;           /* buffer to compose name */
    
    buffer = cmMemoryAllocate(CM_DNS_NAMELEN + 1);
    if (NULL == buffer)
    {
        return NULL;
    }

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
        return NULL;
    }
    return buffer;
}

static void writeBlock(CMRpcPacketDescriptor * writer, const NQ_CHAR * string, const NQ_BYTE * pad, NQ_COUNT sizeOfPad)
{
    dnsEncodeName(writer, string);
    cmRpcPackBytes(writer, pad, sizeOfPad);
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
    writeHeader(&writer, &header);
    writeBlock(&writer, name, query, sizeof(query));

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
    NQ_COUNT maxIps = 0;            /* maximum room in IPs */
    NQ_STATUS res = NQ_FAIL;        /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "type: 0x%x", type);

    if (NULL != pNumIps)
    {
        maxIps = (NQ_COUNT)*pNumIps;
        *pNumIps = 0;
    }
    cmRpcSetDescriptor(&reader, (NQ_BYTE *)buffer, TRUE);
    readHeader(&reader, &header);

    if (DNS_REPLY_CODE_REFUSED == (header.flags2 & DNS_REPLY_CODE))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_ACCESS;   /* force secure exchange */ 
    }    
    if (header.answers < 1 || DNS_REPLY_CODE_NO_SUCH_NAME == (header.flags2 & DNS_REPLY_CODE))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    for (i = header.questions; --i >= 0;)
    {
        if (dnsDecodeName(&reader, NULL) == NQ_FAIL)
        {
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
        }
        cmRpcParseSkip(&reader, 4);
    }
    
    for (answer = 0; answer < header.answers; answer++)
    {  
        NQ_UINT16 t;                        /* next answer type */
        NQ_UINT16 dataLen;                  /* variable data length in answer */
        if (dnsDecodeName(&reader, NULL) == NQ_FAIL)
        {
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
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
                        NQ_IPADDRESS4 * p4;    /* temporary pointer */
                        
                        if (!ip)
                            return NQ_FAIL;
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
                            return NQ_FAIL;
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

                        if (dnsDecodeName(&reader, str) == NQ_FAIL)
                        {
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return NQ_FAIL;
                        }
                        if (name)
                        {
                            syStrncpy(name, str, CM_NQ_HOSTNAMESIZE);
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return NQ_SUCCESS;
                        }
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_FAIL;
                    }    
                case NS_DNS_SRV:
                    {
                        NQ_CHAR str[CM_NQ_HOSTNAMESIZE + 1];    /* host size */

                        cmRpcParseSkip(&reader, 6);
                        if (dnsDecodeName(&reader, str) == NQ_FAIL)
                        {
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return NQ_FAIL;
                        }
                        if (name)
                        {
                            syStrncpy(name, str, CM_NQ_HOSTNAMESIZE);
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return NQ_SUCCESS;
                        }
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_FAIL;
                    }
                case NS_DNS_PTR:
                    {
                        NQ_CHAR str[CM_NQ_HOSTNAMESIZE + 1];    /* host size */

                        if (dnsDecodeName(&reader, str) == NQ_FAIL)
                        {
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return NQ_FAIL;
                        }
                        if (!name)
                        {
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return NQ_FAIL;
                        }

                        syStrncpy(name, str, CM_NQ_HOSTNAMESIZE);
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_SUCCESS;
                    }
                default:
                    {
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_FAIL;
                    }
            }
        }
        else
        {
            cmRpcParseSkip(&reader, dataLen);
        }
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

static NQ_STATUS requestByNameAndType(SYSocketHandle socket, const NQ_CHAR * name, NQ_BYTE type, void * context, const NQ_IPADDRESS * serverIp)
{
    NQ_BYTE buffer[1460];   /* output buffer */
    NQ_UINT length;         /* outgoing packet length */
    NQ_STATUS res;          /* operation result */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res > 0? NQ_SUCCESS : syGetLastError();
}

static NQ_STATUS requestByName(SYSocketHandle socket, const NQ_WCHAR * name, void * context, const NQ_IPADDRESS * serverIp)
{
    NQ_STATUS res;          /* operation result */
    NQ_CHAR * nameA;        /* name as ACSII */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    nameA = cmMemoryCloneWStringAsAscii(name);
    if (NULL == nameA)
    {
        sySetLastError(NQ_ERR_NOMEM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOMEM;
    }
    if (NULL == syStrchr(nameA, '.'))
    {
        NQ_CHAR * qualifiedName = cmMemoryAllocate((NQ_UINT)(syStrlen(nameA) + syStrlen(staticData->dnsDomain) + 2));
        if (NULL == qualifiedName)
        {
            cmMemoryFree(nameA);
            sySetLastError(NQ_ERR_NOMEM);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_ERR_NOMEM;
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
        cmMemoryFree(nameA);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return res;
    }
    res = requestByNameAndType(socket, nameA, NS_DNS_AAAA, context, serverIp);
    cmMemoryFree(nameA);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res == NQ_SUCCESS? 2 : res;
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
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    *numIps = MAX_RESPONSE_IPS;       /* max number of IPs */
    count = syRecvFromSocket(socket, buffer, sizeof(buffer), &srcIp, &srcPort);
    if (count <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving DNS response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)syGetLastError();
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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return res;
    }    
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved %d ips, 1st address: %s", *numIps, cmIPDump(&result[0]));
    
    *pAddressArray = (NQ_IPADDRESS *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_IPADDRESS) * (NQ_UINT)(*numIps)));
    if (NULL == *pAddressArray)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOMEM;
    }
    syMemcpy(*pAddressArray, result, sizeof(NQ_IPADDRESS) * (NQ_UINT)(*numIps));
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

static NQ_STATUS requestByIp(SYSocketHandle socket, const NQ_IPADDRESS * ip, void * context, const NQ_IPADDRESS * serverIp)
{
    NQ_BYTE buffer[1460];   /* output buffer */
    NQ_UINT length;         /* outgoing packet length */
    NQ_STATUS res;          /* operation result */
    NQ_CHAR * ipA;          /* IP as ACSII */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    ipA = createReversedName(ip);
    if (NULL == ipA)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOMEM;
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
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res > 0? NQ_SUCCESS : syGetLastError();
}

static NQ_STATUS responseByIp(SYSocketHandle socket, const NQ_WCHAR ** pName, void ** pContex)
{
    NQ_BYTE buffer[1024];   /* input buffer */
    NQ_INT count;           /* number of bytes in the incoming datagram */
    NQ_IPADDRESS srcIp;     /* source IP */
    NQ_PORT srcPort;        /* source port */
    NQ_CHAR * pNameA;       /* result in ASCII */
    NQ_STATUS res;          /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    count = syRecvFromSocket(socket, buffer, sizeof(buffer), &srcIp, &srcPort);
    if (count <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving DNS response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_STATUS)syGetLastError();
    }

    pNameA = cmMemoryAllocate(CM_DNS_NAMELEN + 1);
    if (NULL == pNameA)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOMEM;
    }
    res = dnsParseQueryResponse(buffer, NS_DNS_PTR, NULL, 0, NULL, pNameA); 
    if (NQ_SUCCESS != res)
    {
        cmMemoryFree(pNameA);
        LOGERR(CM_TRC_LEVEL_ERROR, "Error parsing DNS response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return res;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved name: %s", pNameA);
    
    *pName = cmMemoryCloneAString(pNameA);
    cmMemoryFree(pNameA);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NULL == *pName? NQ_ERR_NOMEM : NQ_SUCCESS;
}

static void parseServerList(NQ_WCHAR * list)
{
    CMResolverMethodDescriptor method;                      /* next method descriptor */
    NQ_WCHAR * curServer;                                   /* pointer to the current server IP */
    NQ_WCHAR * nextServer;                                  /* pointer to the next server IP */
    NQ_CHAR aServer[CM_IPADDR_MAXLEN];                      /* the same in ASCII */

    method.type = NQ_RESOLVER_DNS;
    method.isMulticast = FALSE;  /* unicast */
    method.timeout = 1; /* seconds */
    method.waitAnyway = TRUE;
    method.requestByName = requestByName;
    method.responseByName = responseByName;
    method.requestByIp = requestByIp;
    method.responseByIp = responseByIp;

    syMutexTake(&staticData->guard);
    /* parse servers string */
    for(curServer = list, staticData->numServers = 0; 
        staticData->numServers < sizeof(staticData->dnsServers) / sizeof(staticData->dnsServers[0]); 
        )
    {
        NQ_STATUS res;                      /* operation status */

        nextServer = cmWStrchr(curServer, cmWChar(';'));
        if (NULL != nextServer)
        {
            *nextServer = cmWChar('\0');
        }
        cmUnicodeToAnsi(aServer, curServer);
        res = cmAsciiToIp(aServer, &staticData->dnsServers[staticData->numServers]);
        curServer = nextServer + 1;
        /* register DNS with Resolver */
        cmResolverRemoveMethod(&method, &staticData->dnsServers[staticData->numServers]);
        cmResolverRegisterMethod(&method, &staticData->dnsServers[staticData->numServers]);
        if (NQ_SUCCESS == res)
            staticData->numServers++; 
        if (NULL == nextServer)
        {
            break;
        }
    }

    syMutexGive(&staticData->guard);
}

static void dnsGetServers(void)
{
    NQ_TCHAR * serverListT;                                 /* buffer for DNS servers string */
    NQ_WCHAR * serverListW;                                 /* buffer for DNS servers string in Unicode */
    NQ_TCHAR * domainT;                                     /* buffer for server name */
    CMResolverMethodDescriptor method;                      /* next method descriptor */

    if (staticData->isNewServerSet)
        return;
    serverListT = cmMemoryAllocate(UD_DNS_SERVERSTRINGSIZE * sizeof(NQ_TCHAR));
    domainT = cmMemoryAllocate((CM_NQ_HOSTNAMESIZE + 1) * sizeof(NQ_TCHAR));

    if (NULL == serverListT || NULL == domainT)
    {
        cmMemoryFree(domainT);      /* takes care of NULL */
        cmMemoryFree(serverListT);  /* takes care of NULL */
        return;
    }
    udGetDnsParams(domainT, serverListT);
    cmTcharToAnsi(staticData->dnsDomain, domainT); 
    cmMemoryFree(domainT);   /* take care of NULL */

#ifdef UD_CM_UNICODEAPPLICATION
    serverListW = cmMemoryCloneWString(serverListT);
#else /* UD_CM_UNICODEAPPLICATION */
    serverListW = cmMemoryCloneAString(serverListT);
#endif
    cmMemoryFree(serverListT);  /* takes care of NULL */
    if (NULL == serverListW)
    {
        return;
    }
    parseServerList(serverListW);
    cmMemoryFree(serverListW);  /* takes care of NULL */

    method.type = NQ_RESOLVER_DNS;
    method.isMulticast = TRUE;
    method.timeout = 1; /* seconds */
    method.waitAnyway = TRUE;
    method.requestByName = requestByName;
    method.responseByName = responseByName;
    method.requestByIp = requestByIp;
    method.responseByIp = responseByIp;
#ifdef UD_NQ_USETRANSPORTIPV4
    cmAsciiToIp("224.0.0.252", &staticData->llmnrIp4);
    cmResolverRemoveMethod(&method, &staticData->llmnrIp4);
    cmResolverRegisterMethod(&method, &staticData->llmnrIp4);
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    cmAsciiToIp("FF02:0:0:0:0:0:1:3", &staticData->llmnrIp6);
    cmResolverRemoveMethod(&method, &staticData->llmnrIp6);
    cmResolverRegisterMethod(&method, &staticData->llmnrIp6);
#endif /* UD_NQ_USETRANSPORTIPV6 */
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
    NQ_INT res;                 /* function result */
    NQ_IPADDRESS anyIp4 = CM_IPADDR_ANY4;
    NQ_IPADDRESS tip;           /* dummy */
    NQ_PORT tport;              /* dummy */
#ifdef UD_NQ_USETRANSPORTIPV6
    NQ_IPADDRESS anyIp6 = CM_IPADDR_ANY6;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    socket = syCreateSocket(FALSE, CM_IPADDR_VERSION(*serverIp));
    if (!syIsValidSocket(socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error creating DNS socket");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

#if defined(UD_NQ_USETRANSPORTIPV4) && !defined(UD_NQ_USETRANSPORTIPV6) 
    res = syBindSocket(socket, &anyIp4, 0);
#else
    if (CM_IPADDR_VERSION(*serverIp) == CM_IPADDR_IPV4)
        res = syBindSocket(socket, &anyIp4, 0);
    else
        res = syBindSocket(socket, &anyIp6, 0);
#endif
    if (res == NQ_FAIL)
    {
        syCloseSocket(socket);
        TRCERR("Error binding DNS socket");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    if (sySendToSocket(socket, buffer, dataLength, serverIp, syHton16(DNS_PORT)) == NQ_FAIL)
    {
        syCloseSocket(socket);
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending DNS request");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    syClearSocketSet(&set);
    syAddSocketToSet(socket, &set);

    switch (sySelectSocket(&set, DNS_TIMEOUT))
    {
        case 0:  /* timeout */
            syCloseSocket(socket);
            LOGERR(CM_TRC_LEVEL_ERROR, "DNS Timeout occured");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;

        case -1: /* error or exit */
            syCloseSocket(socket);
            LOGERR(CM_TRC_LEVEL_ERROR, "DNS Error occured");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
    };

    res = syRecvFromSocket(socket, buffer, bufferSize, &tip, &tport);
    syCloseSocket(socket);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
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
    ip4 = (NQ_IPADDRESS4)syGetTime();   
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
    const NQ_BYTE queryData[] = {0, 0xf9, 0, 0x01};
    const NQ_BYTE additionalData[] = {0, 0xf9, 0, 0xff, 0, 0, 0, 0};
    const NQ_BYTE other[] = {0, 0};
#define ALGORITHM_NAME "gss-tsig"
#define TKEY_EXTRALEN 26
#define SECS_IN_DAY (60 * 60 * 24)
#define MODE_GSSAPI 3

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
    writeHeader(&descr, &header);
    writeBlock(&descr, pTkey->name, queryData, sizeof(queryData));
    writeBlock(&descr, pTkey->name, additionalData, sizeof(additionalData));
    cmRpcPackUint16(&descr, (NQ_UINT16)(in->len + TKEY_EXTRALEN));           /* data length */
    cmRpcPackByte(&descr, sizeof(ALGORITHM_NAME) - 1);          /* algorithm as size-prefixed null-terminated */
    cmRpcPackAscii(&descr, ALGORITHM_NAME, CM_RP_NULLTERM);     /* algorithm */
    cmRpcPackUint32(&descr, (NQ_UINT32)syGetTime());                       /* signature creation */
    cmRpcPackUint32(&descr, (NQ_UINT32)(syGetTime() + SECS_IN_DAY));         /* signature expiration */
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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_SUCCESS;
    }

    /* send TKEY payload */
    status = sySendSocket(pTkey->socket, in->data, (NQ_UINT)in->len);
    if (NQ_FAIL == status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to transmit TKEY query");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* send "other" */
    status = sySendSocket(pTkey->socket, other, sizeof(other));
    if (NQ_FAIL == status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to transmit TKEY query");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* receive response */
    syClearSocketSet(&set);
    syAddSocketToSet(pTkey->socket, &set);
    switch (sySelectSocket(&set, DNS_TIMEOUT))
    {
        case 0:  /* timeout */
            LOGMSG(CM_TRC_LEVEL_ERROR, "DNS Timeout occured for TKey request");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;

        case -1: /* error or exit */
            LOGERR(CM_TRC_LEVEL_ERROR, "DNS Error occured");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
    };
    count = (NQ_COUNT)syRecvSocket(pTkey->socket, buffer, sizeof(buffer));
    if (count <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving DNS response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* skip header and queries */
    cmRpcSetDescriptor(&descr, buffer, TRUE);       /* nbo */
    cmRpcParseSkip(&descr, sizeof(NQ_UINT16));      /* packet length */
    readHeader(&descr, &header);
    if ((header.flags2 & 0xF) != 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error DNS response 0x%x", header.flags2);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    
    if (dnsDecodeName(&descr, NULL) == NQ_FAIL)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    cmRpcParseSkip(&descr, 4);

    /* parse answer */
    if (dnsDecodeName(&descr, NULL) == NQ_FAIL)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    cmRpcParseSkip(&descr, 10);            /* type, class, TTL, data length */
    cmRpcParseByte(&descr, &tempByte);     /* algorithm name length */
    cmRpcParseSkip(&descr, (NQ_UINT32)(tempByte + 1));  /* algorithm name */
    cmRpcParseSkip(&descr, 10);            /* times, mode */
    cmRpcParseUint16(&descr, &temp16);     /* error */
    if (0 != temp16)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Server failed the request");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    cmRpcParseUint16(&descr, &temp16);     /* key size */
    out->data = cmMemoryAllocate(temp16);
    if (NULL == out->data)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    out->len = temp16;
    cmRpcParseBytes(&descr, out->data, out->len);     /* key */
    cmRpcParseSkip(&descr, 2);                                      /* other size */

    /* parse additonal record */
    temp16 = (NQ_UINT16)(count - (descr.current - buffer));                      /* tkey length */
    pTkey->tkey.data = cmMemoryAllocate(temp16);
    if (NULL == pTkey->tkey.data)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    pTkey->tkey.len = temp16;
    cmRpcParseBytes(&descr, pTkey->tkey.data, pTkey->tkey.len);     /* tkey */
    pTkey->originalIdOffset = (NQ_INT)(pTkey->tkey.len - 6);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

static NQ_STATUS dnsStartTkey(TkeyContext * pTkey, const NQ_IPADDRESS * serverIp)
{
    NQ_INT ipVersion;               /* v4 or v6 */
    NQ_STATUS status;               /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    status = syConnectSocket(pTkey->socket, serverIp, syHton16(DNS_PORT));
    if (NQ_SUCCESS != status)
    {
        syCloseSocket(pTkey->socket);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect to DNS server over TCP");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    createTkeyName(pTkey->name);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

static void dnsFreeTkeyContext(TkeyContext * pTkey)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
        writeHeader(&descr, &header);
        writeBlock(&descr, service, query, sizeof(query));

        res = dnsDatagramExchange(&staticData->dnsServers[i], buffer, (NQ_COUNT)(descr.current - descr.origin), sizeof(buffer));
        if (res <= 0)
        {
            continue;
        }

        cmRpcSetDescriptor(&descr, buffer, TRUE);
        readHeader(&descr, &header);
        if (header.answers < 1 || DNS_REPLY_CODE_NO_SUCH_NAME == (header.flags2 & DNS_REPLY_CODE))
        {
            continue;
        }
        if (dnsDecodeName(&descr, NULL) == NQ_FAIL)
        {
            continue;
        }
        cmRpcParseSkip(&descr, 4);

        for (answer = 0; answer < header.answers; answer++)
        {  
            NQ_UINT16 t;                          /* next answer type */
            NQ_UINT16 dataLen;                  /* variable data length in answer */

            if (dnsDecodeName(&descr, NULL) == NQ_FAIL)
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
                        if (dnsDecodeName(&descr, str) == NQ_FAIL)
                        {
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return NQ_FAIL;
                        }
                        syStrncpy(host, str, CM_NQ_HOSTNAMESIZE);
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_SUCCESS;
                    }    
                default:
                    {
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_FAIL;
                    }
            }
            answer++;
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_FAIL;
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
    writeHeader(&descr, &header);
    domain = syStrchr(host, '.');
    if (NULL == domain)
        return NQ_FAIL;
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
                    return NQ_FAIL;
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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    cmRpcSetDescriptor(&descr, buffer, TRUE);
    readHeader(&descr, &header);
    if (DNS_REPLY_CODE_REFUSED == (header.flags2 & DNS_REPLY_CODE))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return DNS_REPLY_CODE_REFUSED;   /* force secure exchange */ 
    }
    if (0 != (header.flags2 & DNS_REPLY_CODE))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */

/* perform on all servers, forcing TKey query if needed */ 
static NQ_STATUS dnsUpdate(
    NQ_UINT16 type,
    NQ_IPADDRESS *hostIPs,
    NQ_UINT16 numHostIPs
    )
{
#ifndef UD_CM_DONOTREGISTERHOSTNAMEDNS
    NQ_COUNT i;                             /* index in DNS servers */
    NQ_STATUS status = NQ_FAIL;             /* operation result */
    NQ_CHAR host[CM_NQ_HOSTNAMESIZE + 1];   /* self host name */
    NQ_STATUS res = NQ_FAIL;                /* update status */
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
#ifdef UD_CM_DONOTREGISTERHOSTNAMEDNS
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NQ_SUCCESS;
#else
    dnsNormalizeName(cmGetFullHostName(), host);

    /* try request with each of the DNS servers until one of them suceeds */
    dnsGetServers();

    for (i = 0; i < staticData->numServers; i++)
    {
        status = dnsUpdateOneServer(type, &staticData->dnsServers[i], host, hostIPs, numHostIPs, NULL);
#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)
        if (DNS_REPLY_CODE_REFUSED == status)    /* secure exchange required */
        {
            TkeyContext context;            /* secure authentication exchange */
            AMCredentialsW * pCredentials;  /* user credentials */
    	    AMCredentials * pCredentialsT;	/* credentials allocated */
            const NQ_WCHAR * hostW;         /* host name in Unicode */
	        
            pCredentialsT = (AMCredentials *)cmMemoryAllocate(sizeof(AMCredentials));
            pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentials));
            hostW = cmMemoryCloneAString(host);
            if (NULL == pCredentials || NULL == pCredentialsT || NULL == hostW)
            {
    		    cmMemoryFree(pCredentials);
    		    cmMemoryFree(pCredentialsT);
                cmMemoryFree(hostW);
		        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                sySetLastError(NQ_ERR_NOMEM);
		        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		        return NQ_FAIL;
            }
    	    if (!udGetCredentials(hostW, pCredentialsT->user, pCredentialsT->password, pCredentialsT->domain.name))
	        {
                cmMemoryFree(hostW);
    		    cmMemoryFree(pCredentials);
    		    cmMemoryFree(pCredentialsT);
		        LOGERR(CM_TRC_LEVEL_ERROR, "udGetCredentials break by user");
		        sySetLastError(NQ_ERR_BADPARAM);
	    	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		        return NQ_FAIL;
	        }
            cmTcharToUnicode(pCredentials->domain.name, pCredentialsT->domain.name);
            cmWStrupr(pCredentials->domain.name);
            cmTcharToUnicode(pCredentials->user, pCredentialsT->user);
            cmTcharToUnicode(pCredentials->password, pCredentialsT->password);
      	    cmMemoryFree(pCredentialsT);
            status = dnsStartTkey(&context, &staticData->dnsServers[i]);
    	    if (NQ_SUCCESS != status)
            {
                cmMemoryFree(hostW);
		        cmMemoryFree(pCredentials);
    	        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	            return NQ_FAIL;
            }
    
            status = amSpnegoClientLogon(&context, NULL, pCredentials, FALSE, NULL, &context.sessionKey, &context.macKey, dnsQueryTkey);
            if (AM_SPNEGO_SUCCESS == status)
            {
                status = dnsUpdateOneServer(type, &staticData->dnsServers[i], host, hostIPs, numHostIPs, &context);
            }
            dnsFreeTkeyContext(&context);
            cmMemoryFree(hostW);
   		    cmMemoryFree(pCredentials);
        }
#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */
        if (NQ_SUCCESS == status)
            res = NQ_SUCCESS;
    }
    staticData->isRegistered = TRUE;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
#endif /* UD_CM_DONOTREGISTERHOSTNAMEDNS */
}

/* -- API functions -- */

NQ_STATUS nsDnsInit(void)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate DNS data");
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    syMutexCreate(&staticData->guard);
    staticData->id = 1;
    staticData->isRegistered = FALSE;
    staticData->isNewServerSet = FALSE;
    dnsGetServers();    /* to have domain name */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
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
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

NQ_STATUS nsDnsGetHostNameByService(const NQ_CHAR * service, NQ_CHAR * name)
{
    NQ_CHAR tmp[CM_NQ_HOSTNAMESIZE + 1];

    if (NULL == name || NULL == service || 0 == syStrlen(service))
        return NQ_FAIL;

    dnsNormalizeName(service, tmp);
    return dnsQueryService(tmp, name);
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
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_SUCCESS;
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

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}

void cmDnsSetServersA(const NQ_CHAR * servers)
{
    const NQ_WCHAR * serversW;      /* unicode copy */

    if (NULL == servers)
    {
    	cmDnsSetServersW(NULL);
        return;
    }

    serversW = cmMemoryCloneAString(servers);
    if (NULL != serversW)
        cmDnsSetServersW(serversW);
    cmMemoryFree(serversW);
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
	if (domainName == NULL ||syStrlen(domainName) > (CM_NQ_HOSTNAMESIZE +1) || syStrlen(domainName) < 1 )
	{
		return NQ_FAIL;
	}

	syMutexTake(&staticData->guard);

	syStrcpy(staticData->dnsDomain , domainName);
	staticData->isNewServerSet = TRUE;

	syMutexGive(&staticData->guard);

	return NQ_SUCCESS;
}

NQ_STATUS cmDnsSetDomainW(
		const NQ_WCHAR * domainName
		)
{
	NQ_CHAR domainNameA[CM_NQ_HOSTNAMESIZE + 1];

	if (domainName == NULL)
		return NQ_FAIL;

	cmUnicodeToAnsi((NQ_CHAR *)&domainNameA , domainName);

	return cmDnsSetDomainA((const NQ_CHAR *)&domainNameA);

}
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */
