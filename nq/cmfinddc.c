/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Domain controller discovery library
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 20-Jan-2005
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmcrypt.h"
#include "nsapi.h"
#include "nqapi.h"

#include "cmfinddc.h"
#ifdef UD_NQ_INCLUDESMB2
#include "cmsmb2.h"
#endif /* UD_NQ_INCLUDESMB2 */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
#include "cmgssapi.h"
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

/*
    defines
*/

#define OPCODE_NETLOGONQUERY    ((NQ_BYTE)7)
#define OPCODE_NETLOGONRESPONSE ((NQ_BYTE)12)
#define MS_REQ_NETLOGONQUERY    "\\MAILSLOT\\NET\\NETLOGON"     /* NETLOGON_QUERY request mailslot name */
#define MS_RSP_NETLOGONQUERY    "\\MAILSLOT\\TEMP\\NETLOGON"    /* NETLOGON_QUERY response mailslot name */
#define LM20TOKEN               ((NQ_UINT16)0xFFFF)

#define PASSTHROUGH_TIMEOUT     10
#define TRANSACTION_TIMEOUT     ((NQ_UINT32)1000)
#define PDC_QUERY_TIMEOUT       5
#define TRANSACTION_SETUP_COUNT 3

#define EXISTING_PDC_TTL 60          /* timeout for cache entry in seconds */
#define NONEXISTING_PDC_TTL 10       /* the same when no PDC was found */

typedef struct
{
    CMItem item;                                /* inherited object */
    NQ_TIME time;                               /* time when this entry was cached */
    NQ_TIME ttl;                                /* time to live */
    NQ_BOOL exists;                             /* TRUE if the PDC exists, FALSE oetherwise */
    NQ_CHAR pdcName[CM_NQ_HOSTNAMESIZE + 1];    /* PDC name */
}
CacheEntry;          /* an association between domain name and host name */

/* 
    static data 
*/

typedef struct
{
    NQ_BOOL pdcDiscovered;                      /* whether PDC was found already */
    NQ_CHAR pdcName[CM_NQ_HOSTNAMESIZE + 1];    /* PDC name                      */
    const NQ_CHAR *domainName;                  /* domain name                   */ 
    CMList cache;                               /* cached domains */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* 
   functions 
*/

/*
 *====================================================================
 * PURPOSE: Initialize find DC resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   
 *====================================================================
 */

NQ_STATUS
cmFindDCInit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
       LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
       return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */
    staticData->pdcDiscovered = FALSE;  
    staticData->domainName = NULL;
    cmListStart(&staticData->cache);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Release find DC resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   
 *====================================================================
 */

void
cmFindDCExit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    cmListShutdown(&staticData->cache);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: attach NETBIOS buffer to a packet
 *--------------------------------------------------------------------
 * PARAMS:  IN  packet
 *          IN  buffer
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmPacketAttachBuffer(CMSmbPacket *packet, NQ_BYTE *buffer)
{
    packet->buffer = buffer;
    packet->header = (CMCifsHeader*)nsSkipHeader(NULL, packet->buffer);
    packet->words = NULL;
    packet->bytes = NULL;
    packet->size = 0;
}

/*
 *====================================================================
 * PURPOSE: clear packet buffer and initialize it with  proper CIFS
 *          protocol header
 *--------------------------------------------------------------------
 * PARAMS:  IN  packet
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void pcktClear(CMSmbPacket *packet)
{
    TRC("Clearing packet buffer");

    /* clear SMB buffer area */
    syMemset(packet->header, 0, CM_NB_DATAGRAMBUFFERSIZE - sizeof(CMNetBiosSessionMessage));
    /* set protocol identification */
    syMemcpy(packet->header->protocol, "\xFFSMB", 4);

    packet->words = (CMCifsWordBlock *)(packet->header + 1);
    packet->size = sizeof(CMCifsHeader);
}

static void validateCache()
{
    CMIterator iterator;            /* for iterating cache items */
    NQ_TIME curTime;                /* current time in seconds */

    curTime  = (NQ_TIME)syGetTime();
    cmListIteratorStart(&staticData->cache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        const CacheEntry * pEntry;   /* next cache entry */
        
        pEntry = (const CacheEntry *)cmListIteratorNext(&iterator);
        if (pEntry->ttl < (curTime - pEntry->time))
        {
            cmListItemRemoveAndDispose((CMItem *)pEntry);
        }
    }
    cmListIteratorTerminate(&iterator);
}

static const CacheEntry * lookupNameInCache(const NQ_CHAR * name)
{
    NQ_WCHAR * nameW;                       /* name in Unicode */
    const CacheEntry * result = NULL;       /* lookup result */   

    nameW = cmMemoryCloneAString(name);
    if (NULL != nameW)
    {
        validateCache();
        result = (const CacheEntry *)cmListItemFind(&staticData->cache, nameW, TRUE , FALSE);
        cmMemoryFree(nameW);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
    }
    return result;
}

static void addToCache(const NQ_CHAR * domain, const NQ_CHAR * pdc, NQ_BOOL exists)
{
    NQ_WCHAR * nameW;               /* name in Unicode */
    CacheEntry * pEntry;            /* new entry */   

    nameW = cmMemoryCloneAString(domain);
    if (NULL == nameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        return;
    }
    pEntry = (CacheEntry *)cmListItemCreateAndAdd(&staticData->cache, sizeof(CacheEntry), nameW, NULL, FALSE);
    cmMemoryFree(nameW);
    if (NULL == pEntry)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        return;
    }
    pEntry->exists = exists;
    pEntry->time = (NQ_TIME)syGetTime();
    pEntry->ttl = exists? EXISTING_PDC_TTL : NONEXISTING_PDC_TTL;
    syStrncpy(pEntry->pdcName, pdc, sizeof(pEntry->pdcName));
}

/*
 *====================================================================
 * PURPOSE: set packet command code and word parameters count (byte
 *          data start address is calculated)
 *--------------------------------------------------------------------
 * PARAMS:  IN  packet
 *          IN  command code
 *          IN  number of words in word params
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void pcktSetCommand(
    CMSmbPacket *packet,
    NQ_BYTE command,
    NQ_BYTE words
    )
{
    TRC2P("Packet command: %d, words: %d", command, words);

    packet->header->command = command;
    packet->words->count = words;
    packet->bytes = (CMCifsByteBlock *)((NQ_BYTE *)packet->words + cmCifsSizeofWordParam((NQ_UINT)(words * 2)));
}

/*
 *====================================================================
 * PURPOSE: mark packet end - determine packet byte data count and
 *          total size
 *--------------------------------------------------------------------
 * PARAMS:  IN  packet
 *          IN  end address
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static
void
pcktSetEnd(CMSmbPacket *packet, NQ_BYTE *end)
{
    TRC3P("Finalizing packet - words: %d, bytes: %ld, total size: %ld",
          packet->words->count, (NQ_UINT32)(end - packet->bytes->data), (NQ_UINT32)(end - (NQ_BYTE *)packet->header));

    /* calculate byte count and packet size */
    cmPutSUint16(packet->bytes->count, cmHtol16((NQ_UINT16)(end - packet->bytes->data)));
    packet->size = (NQ_UINT)(end - (NQ_BYTE *)packet->header);
}

/*
 *====================================================================
 * PURPOSE: set word parameters and byte data addresses for newly
 *          received packet and convert flags2 and byte data count
 *          values from the network byte order to the host order
 *--------------------------------------------------------------------
 * PARAMS:  IN  packet
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void pcktNormalize(CMSmbPacket *packet)
{
    cmPutSUint16(packet->header->flags2, cmLtoh16(cmGetSUint16(packet->header->flags2)));
    packet->words = (CMCifsWordBlock *)(packet->header + 1);
    packet->bytes = (CMCifsByteBlock *)((NQ_BYTE *)packet->words + cmCifsSizeofWordParam((NQ_UINT)(packet->words->count * 2)));
    cmPutSUint16(packet->bytes->count, cmLtoh16(cmGetSUint16(packet->bytes->count)));

    TRC3P("Packet normalized - flags2: %d, words: %d, bytes: %d",
          cmGetSUint16(packet->header->flags2), packet->words->count, cmGetSUint16(packet->bytes->count));
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

/*
 *====================================================================
 * PURPOSE: pad pointer to a given size
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer
 *          IN  size to pad
 *
 * RETURNS: padded pointer
 *
 * NOTES:
 *====================================================================
 */

#ifndef UD_NQ_AVOIDDCRESOLUTIONNETBIOS

static NQ_BYTE * pad(NQ_BYTE *ptr, NQ_UINT size)
{
    NQ_BYTE *result = ptr - ((NQ_ULONG)ptr & (size - 1));

    if (result != ptr)
        result += size;

    return result;
}

#endif /* UD_NQ_AVOIDDCRESOLUTIONNETBIOS */

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: send given packet to server through already established
 *          and supplied connection and get server response packet
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection
 *          IN  UID
 *          IN  packet to send
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:   the response data will be stored in the same packet
 *====================================================================
 */

static NQ_UINT32 exchangeTcpPackets(CMSmbConnection *connection, NQ_UINT16 uid, CMSmbPacket *packet)
{
    static const NQ_UINT16 mid = 0;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* Encode some header info */
    cmPutSUint16(packet->header->mid, mid);
    cmPutSUint16(packet->header->uid, uid);

    /* if unicode enabled set the appropriate flag2 bit */
    if (connection->unicode)
        cmPutSUint16(packet->header->flags2, cmGetSUint16(packet->header->flags2) | cmHtol16(SMB_FLAGS2_UNICODE));

    connection->sequence++;

    TRC1P("Sending packet of size %d", packet->size);

    /* send the request packet (the function gets the whole buffer including the NETBIOS part) */
    if (nsSendFromBuffer(
            connection->socket, 
            packet->buffer, 
            packet->size, 
            packet->size, 
            NULL
            ) != NQ_FAIL)
    {
        NSSocketSet set;
        NQ_INT length, expected;
        NSRecvDescr recvDescr;

        /* get the response packet */
        nsClearSocketSet(&set);
        nsAddSocketToSet(&set, connection->socket);

        switch (nsSelect(&set, PASSTHROUGH_TIMEOUT))
        {
            case 0:
                LOGERR(CM_TRC_LEVEL_ERROR, "select() timeout");
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NQ_ERR_TIMEOUT;

            case NQ_FAIL:
                LOGERR(CM_TRC_LEVEL_ERROR, "nsSelect() failed");
                break;

            default:
                expected = nsStartRecvIntoBuffer(connection->socket, &recvDescr);
                if (expected == 0 || expected == NQ_FAIL)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "unable to read NBT header");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_ERR_GENERAL;
                }

                if ((length = nsRecvIntoBuffer(&recvDescr, packet->buffer + 4, (NQ_COUNT)expected)) != NQ_FAIL)
                {
                    TRC3P("Received stream packet - length: %d, status: %ld, mids match: %s", length, (packet->header->status), (mid == cmGetSUint16(packet->header->mid) ? "YES" : "NO"));

                    nsEndRecvIntoBuffer(&recvDescr);

                    connection->sequence++;
                    if (cmGetSUint32(packet->header->status) == 0)
                        pcktNormalize(packet);

                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return cmGetSUint32(packet->header->status);
                }
                else
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "nsRecvIntoBuffer() failed");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_ERR_GETDATA;
                }
        }
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "nsSendFromBuffer() failed");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_ERR_GENERAL;
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

/*
 *====================================================================
 * PURPOSE: send given datagram packet to one name or to a group and
 *          receive the response packet
 *--------------------------------------------------------------------
 * PARAMS:  IN  datagram socket
 *          IN  destination name
 *          IN  packet to send
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:   the response data will be stored in the same packet
 *====================================================================
 */

#ifndef UD_NQ_AVOIDDCRESOLUTIONNETBIOS

static NQ_STATUS exchangeUdpPackets(
    NSSocketHandle socket,          /* datagram socket */
    CMNetBiosNameInfo *to,          /* destination name */
    CMSmbPacket *packet
    )
{
    CMNetBiosNameInfo from;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (nsSendToName(socket, (NQ_BYTE*)packet->header, packet->size, to) != NQ_FAIL)
    {
        NSSocketSet set;
        NQ_INT length;

        nsClearSocketSet(&set);
        nsAddSocketToSet(&set, socket);

        switch(nsSelect(&set, PDC_QUERY_TIMEOUT))
        {
            case 0:
                LOGERR(CM_TRC_LEVEL_ERROR, "select() timeout");
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NQ_ERR_TIMEOUT;

            case NQ_FAIL:
                LOGERR(CM_TRC_LEVEL_ERROR, "Error on select for transaction frame");
                break;

            default:
                length = nsRecvFromName(socket, (NQ_BYTE*)packet->header, CIFS_MAX_DATA_SIZE16, &from);

                if (length != NQ_FAIL)
                {
                    TRC2P("Received datagram packet - length: %d, status: %ld", length, cmGetSUint32(packet->header->status));

                    if (cmGetSUint32(packet->header->status) == 0)
                        pcktNormalize(packet);
                    else
                    {
                        cmPutSUint32(packet->header->status, cmLtoh32(cmGetSUint32(packet->header->status)));
                    }

                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return (NQ_STATUS)cmGetSUint32(packet->header->status);
                }
                else
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving transaction frame");
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_ERR_GETDATA;
                }
        }
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "nsSendToName() failed");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_ERR_GENERAL;
}

#endif /* UD_NQ_AVOIDDCRESOLUTIONNETBIOS */

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: negotiate a connection that is already established
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection
 *          IN  an empty packet
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32 negotiate(
    CMSmbConnection *connection,
    CMSmbPacket *packet
    )
{
    NQ_UINT32 status;
    NQ_BYTE *data;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    connection->negotiated = FALSE;
    connection->unicode = FALSE;
    connection->sequence = 0;
    connection->key = 0;

    pcktClear(packet);
    pcktSetCommand(packet, SMB_COM_NEGOTIATE, 0);

    data = packet->bytes->data;

    *data++ = 2;  /* buffer format type: dialect */
    syStrcpy((NQ_CHAR*)data, CM_DIALECT_NT_LM_012);

    pcktSetEnd(packet, data + sizeof(CM_DIALECT_NT_LM_012));

    if ((status = exchangeTcpPackets(connection, 0, packet)) == NQ_ERR_OK)
    {
        CMCifsNegotiateResponse *response = (CMCifsNegotiateResponse *)packet->words;

        TRC2P("Negotiate response - dialect index: %d, security mode: %d", cmGetSUint16(response->dialectIndex), response->securityMode);

        if (cmGetSUint16(response->dialectIndex) == 0 && (response->securityMode & SMB_SECURITY_ENCRYPT_PASSWORD) != 0 &&
            (cmLtoh32(cmGetSUint32(response->capabilities)) & SMB_CAP_EXTENDED_SECURITY) == 0 &&
            response->encryptKeyLength == SMB_ENCRYPTION_LENGTH)
        {
            connection->negotiated = TRUE;
            connection->key = cmLtoh32(cmGetSUint32(response->sessionKey));
            syMemcpy(connection->encryption, packet->bytes->data, SMB_ENCRYPTION_LENGTH);
            connection->unicode = (cmLtoh16(cmGetSUint16(packet->header->flags2)) & SMB_FLAGS2_UNICODE) != 0;
            TRC1P("Connection negotiated successfully, key = %ld", connection->key);
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Invalid dialect index or unsupported security mode");
            status = NQ_ERR_GENERAL;
        }
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "exchangeTcpPackets failed");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}

/*
 *====================================================================
 * PURPOSE: perform session setup
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection
 *          IN  session to setup
 *          IN  an empty packet
 *          IN  user name to use for the session
 *          IN  LM password
 *          IN  LM password length
 *          IN  NTLM password
 *          IN  NTLM password length
 *          IN  logon domain name
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
cmSetupSession(
    CMSmbConnection *connection,
    CMSmbSession *session,
    CMSmbPacket *packet,
    const NQ_TCHAR *user,
    const NQ_BYTE *pwdLM,
    NQ_INT pwdLMLength,
    const NQ_BYTE *pwdNTLM,
    NQ_INT pwdNTLMLength,
    const NQ_CHAR *domain
    )
{
    CMCifsSessionSetupAndXRequest *ssax;
    NQ_BYTE *data;
    NQ_UINT32 status;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    connection->sequence = 0;

    session->setup = FALSE;
    session->uid = 0;

    TRC1P("Sending SessionSetupAnxX packet with user name: %s", cmTDump(user));

    pcktClear(packet);
    pcktSetCommand(packet, SMB_COM_SESSION_SETUP_ANDX, SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT);

    ssax = (CMCifsSessionSetupAndXRequest *)packet->words;
    /* Encode _session setup data */
    ssax->andXCommand = SMB_COM_NO_ANDX_COMMAND;
    cmPutSUint16(ssax->maxBufferSize, cmHtol16(CIFS_MAX_DATA_SIZE16));
    cmPutSUint16(ssax->maxMpxCount, cmHtol16(1));
    /* ssax->VcNumber = 0; */ /* zero anyway - skipped */
    cmPutSUint32(ssax->sessionKey, cmHtol32(connection->key));
    cmPutSUint16(ssax->caseInsensitivePasswordLength, cmHtol16((NQ_UINT16)pwdLMLength));
    cmPutSUint16(ssax->caseSensitivePasswordLength, cmHtol16((NQ_UINT16)pwdNTLMLength));

    data = packet->bytes->data;

    syMemcpy(data, pwdLM, pwdLMLength);
    data += pwdLMLength;
    syMemcpy(data, pwdNTLM, pwdNTLMLength);
    data += pwdNTLMLength;

    if (connection->unicode)
    {
        cmPutSUint32(ssax->capabilities, cmGetSUint32(ssax->capabilities) | cmLtoh32(SMB_CAP_UNICODE));
        *data++ = 0;
    }

    data = cmTcharToStr(data, user, connection->unicode);
    data = cmAnsiToStr(data, domain, connection->unicode);
    data = cmAnsiToStr(data, CM_NATIVE_OS, connection->unicode);
    data = cmAnsiToStr(data, CM_NATIVE_LANMAN, connection->unicode);

    pcktSetEnd(packet, data);

    /* send the packet and receive server response */
    if ((status = exchangeTcpPackets(connection, 0, packet)) == NQ_ERR_OK)
    {
        session->uid = cmGetSUint16(packet->header->uid);
        session->setup = TRUE;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}

/*
 *====================================================================
 * PURPOSE: close connection
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection to close
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmCloseConnection(
    CMSmbConnection *connection
    )
{
    NQ_IPADDRESS zero = CM_IPADDR_ZERO;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    connection->established = FALSE;

    if (connection->socket != NULL)
    {
        TRC1P("Closing connection to: %s", connection->host.name);

        nsClose(connection->socket);

        connection->socket = NULL;
        connection->host.name[0] = '\0';
        connection->ip = zero;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: returns the list of transports by their priorities
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: the pointer to array of transports following by zero
 *
 * NOTES:
 *====================================================================
 */
NQ_UINT*
cmGetTransportPriorities(
    void
    )
{
    static const NQ_UINT defaultTransports[] = {
#ifdef UD_NQ_USETRANSPORTIPV4
          NS_TRANSPORT_IPV4,
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTNETBIOS
          NS_TRANSPORT_NETBIOS,
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_USETRANSPORTIPV6
          NS_TRANSPORT_IPV6,
#endif /* UD_NQ_USETRANSPORTIPV6 */
          0 } ;

    static NQ_UINT priorities[sizeof(defaultTransports)/sizeof(NQ_UINT) + 1] = {0};

    if (priorities[0] == 0)
    {
        const NQ_UINT *t;
        NQ_INT i, p;

        /* lets walk through priorities */
        for (p = 3, i = 0; p > 0; p--)
        {
            /* lets try all transports */
            for (t = defaultTransports; *t; t++)
            {
                if (udGetTransportPriority(*t) == p)
                    priorities[i++] = *t;
            }
        }

        priorities[i++] = 0;
    }

    return priorities;
}

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
/*
 *====================================================================
 * PURPOSE: negotiate a connection that is already established 
 *          (using extended security)
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection
 *          IN  an empty packet
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:
 *====================================================================
 */
 
static
NQ_UINT32
negotiateExtSecSMB(
    CMSmbConnection *connection,
    CMSmbPacket *packet
    )
{
    NQ_UINT32 status;
    NQ_BYTE *data;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    connection->negotiated = FALSE;
    connection->sequence = 0;
    connection->key = 0;
    connection->unicode = TRUE;

    pcktClear(packet);
    pcktSetCommand(packet, SMB_COM_NEGOTIATE, 0);

    /* set flags */
    cmPutSUint16(packet->header->flags2, cmHtol16(SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_32_BIT_ERROR_CODES));
    
    data = packet->bytes->data;

    *data++ = 2;  /* buffer format type: dialect */
    syStrcpy((NQ_CHAR*)data, CM_DIALECT_NT_LM_012);

    pcktSetEnd(packet, data + sizeof(CM_DIALECT_NT_LM_012));

    if ((status = exchangeTcpPackets(connection, 0, packet)) == NQ_ERR_OK)
    {
        CMCifsNegotiateResponse *response = (CMCifsNegotiateResponse *)packet->words;

        if (cmGetSUint16(response->dialectIndex) == 0 && (response->securityMode & SMB_SECURITY_ENCRYPT_PASSWORD) != 0 &&
            (cmLtoh32(cmGetSUint32(response->capabilities)) & SMB_CAP_EXTENDED_SECURITY) != 0 &&
            cmGssDoesBlobHaveMechType((NQ_BYTE *)(response + 1) + 8, cmLtoh16(cmGetSUint16(response->byteCount)), &cmGssApiOidNtlmSsp))
        {
            connection->negotiated = TRUE;
            connection->unicode = (cmLtoh16(cmGetSUint16(packet->header->flags2)) & SMB_FLAGS2_UNICODE) != 0;
            TRC("Connection negotiated successfully");
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Invalid dialect index or unsupported security mode");
            status = NQ_ERR_GENERAL;
        }
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "exchangeTcpPackets failed");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

#ifdef UD_NQ_INCLUDESMB2
#if 0
/*
 *====================================================================
 * PURPOSE: negotiate a connection that is already established 
 *          (using SMB2)
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection
 *          IN  an empty packet
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:
 *====================================================================
 */
static
NQ_STATUS
negotiateExtSecSMB2(
    CMSmbConnection *connection,
    CMSmbPacket *packet
    )
{
    NQ_STATUS status;
    CMBufferWriter *writer;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    connection->negotiated = FALSE;
    connection->unicode = FALSE;
    connection->sequence = 0;
    connection->key = 0;

    /* create negotiate smb2 request */
    syMemset(packet->buffer, 0, 4 + 102);
    syMemcpy(packet->buffer + 4, cmSmb2ProtocolId, sizeof(cmSmb2ProtocolId));
    cmBufferWriterInit(writer, packet->buffer + 4, 102);
    cmBufferWriterSkip(writer, sizeof(cmSmb2ProtocolId));
    cmBufferWriteUint16(writer, SMB2_HEADERSIZE);
    cmBufferWriterSkip(writer, SMB2_HEADERSIZE - 6);
    cmBufferWriteUint16(writer, 36);
    cmBufferWriteUint16(writer, 1);
    cmBufferWriterSkip(writer, 32);
    cmBufferWriteUint16(writer, SMB2_DIALECTREVISION);
    TRCDUMP("packet to send", packet->buffer, 102);

    packet->size = 102;

    if ((status = exchangeTcpPackets(connection, 0, packet)) == NQ_ERR_OK)
    {
        TRC("Negotiate response accepted");
        connection->negotiated = TRUE;
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "exchangeTcpPackets failed");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}
#endif 
#endif  /* UD_NQ_INCLUDESMB2 */


#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
/*  */
/*
 *====================================================================
 * PURPOSE: perform negotiate with extended security 
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection
 *          IN  an empty packet
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:
 *====================================================================
 */
 
static
NQ_UINT32
negotiateExtendedSecurity(
    CMSmbConnection *connection,
    CMSmbPacket *packet
    )
{   
    NQ_UINT32 status;
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
  
#ifdef UD_NQ_INCLUDESMB2
#if 0  
    /* todo: check whether smb2 expected */
    if (negotiateExtSecSMB2(connection, packet) == NQ_SUCCESS)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_SUCCESS;
    }
    /* fallback to SMB */
#endif
#endif /* UD_NQ_INCLUDESMB2 */

    status = negotiateExtSecSMB(connection, packet);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

/*
 *====================================================================
 * PURPOSE: establish a negotiated connection with given server
 *--------------------------------------------------------------------
 * PARAMS:  IN  server name
 *          IN  connection
 *          IN  an empty packet
 *          IN  whether extended security should be negotiated
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
cmConnectAndNegotiate(
    const NQ_CHAR *server,
    CMSmbConnection *connection,
    CMSmbPacket *packet,
    NQ_UINT transport
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    ,
    NQ_BOOL extendedSecurity
#endif    
    )
{
    NQ_UINT32 result = NQ_ERR_NORESOURCE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    connection->established = FALSE;

    if ((connection->socket = nsSocket(NS_SOCKET_STREAM, transport)) != NULL)
    {
        const NQ_IPADDRESS * ips;       /* resolved IPs */
        NQ_WCHAR * serverW;             /* server name in Unicode */ 
        NQ_INT numIps;                  /* number of resolved IPs */

        LOGMSG(CM_TRC_LEVEL_FUNC_COMMON, "Resolving %s IP address...", server);

        serverW = cmMemoryCloneAString(server);
        if (NULL == serverW)
        {
            cmCloseConnection(connection);
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            return NQ_ERR_NOMEM;
        }
        ips = cmResolverGetHostIps(serverW, &numIps);
        cmMemoryFree(serverW);
        if (NULL == ips)
        {
            cmCloseConnection(connection);
            LOGERR(CM_TRC_LEVEL_ERROR, "'%s' not resolved", server);
            return NQ_ERR_NOTFOUND;
        }

        for (; numIps > 0; numIps--)
        {
            connection->ip = ips[numIps - 1];       /* IP to use */
            switch (transport)
            {
    #ifdef UD_NQ_USETRANSPORTNETBIOS
                case NS_TRANSPORT_NETBIOS:
                    if (CM_IPADDR_IPV4 != CM_IPADDR_VERSION(connection->ip))
                        continue;
                    break;
    #endif /* UD_NQ_USETRANSPORTNETBIOS */
    #ifdef UD_NQ_USETRANSPORTIPV4
                case NS_TRANSPORT_IPV4:
                    if (CM_IPADDR_IPV4 != CM_IPADDR_VERSION(connection->ip))
                        continue;
                    break;
    #endif /* UD_NQ_USETRANSPORTIPV4 */

    #ifdef UD_NQ_USETRANSPORTIPV6
                case NS_TRANSPORT_IPV6:
                    if (CM_IPADDR_IPV6 != CM_IPADDR_VERSION(connection->ip))
                        continue;
                    break;
    #endif /* UD_NQ_USETRANSPORTIPV6 */
            }

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Now connecting...");
            if (nsConnect(connection->socket, &connection->ip, &connection->host) != NQ_FAIL)
            {
                connection->established = TRUE;

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Connected to %s, now negotiating...", connection->host.name);

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
                if (extendedSecurity) 
                {
                    result = negotiateExtendedSecurity(connection, packet);
                }
                else
#endif 
                {
                    result = negotiate(connection, packet);
                }
                
                if (result == NQ_ERR_OK)
                {
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "New connection negotiated successfully");
                }
                else
                {
                    cmCloseConnection(connection);
                    LOGERR(CM_TRC_LEVEL_ERROR, "negotiate() failed");
                }
            }
            else
            {
                result = NQ_ERR_NOTCONNECTED;
                cmCloseConnection(connection);
                LOGERR(CM_TRC_LEVEL_ERROR, "nsConnect() failed");
            }
            if (NQ_ERR_OK == result)
                break;                  /* success */
        }
        cmMemoryFree(ips);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "nsSocket() failed");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result;
}

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
/*
 *====================================================================
 * PURPOSE: perform session setup with extended security
 *--------------------------------------------------------------------
 * PARAMS:  IN   connection
 *          IN   session to setup
 *          IN   an empty packet
 *          IN   pointer to security blob received from client
 *          IN   pointer to security blob length
 *          IN/OUT  pointer to security blob received from PDC
 *          IN/OUT  pointer to security blob length
 *
 * RETURNS: NQ_ERR_OK if succeded, error code otherwise
 *
 * NOTES:
 *====================================================================
 */
NQ_UINT32
cmSetupSessionExtendedSecurity(
    CMSmbConnection *connection,
    CMSmbSession *session,
    CMSmbPacket *packet,
    const NQ_BYTE *inBlob,
    const NQ_UINT16 inBlobLength,
    NQ_BYTE* pOutBlob,
    NQ_COUNT* pOutBlobLength
    )
{
    CMCifsSessionSetupAndXSSPRequest *request;
    CMCifsSessionSetupAndXSSPResponse *response;
    NQ_BYTE *data;
    NQ_UINT32 result;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    connection->sequence = 0;
    session->setup = FALSE;

    pcktClear(packet);
    cmPutSUint16(packet->header->flags2, cmHtol16(SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_32_BIT_ERROR_CODES));
    pcktSetCommand(packet, SMB_COM_SESSION_SETUP_ANDX, SMB_SESSIONSETUPANDXSSP_REQUEST_WORDCOUNT);

    request = (CMCifsSessionSetupAndXSSPRequest *)packet->words;
    request->andXCommand = SMB_COM_NO_ANDX_COMMAND;
    cmPutSUint16(request->maxBufferSize, cmHtol16(CIFS_MAX_DATA_SIZE16));
    cmPutSUint16(request->maxMpxCount, cmHtol16(1));
    cmPutSUint32(request->sessionKey, 0);
    cmPutSUint16(request->blobLength, cmHtol16(inBlobLength));

    data = packet->bytes->data;
    syMemcpy(data, inBlob, inBlobLength);
    data += inBlobLength;
    cmPutSUint32(request->capabilities, cmGetSUint32(request->capabilities) | cmLtoh32(SMB_CAP_UNICODE | SMB_CAP_EXTENDED_SECURITY | SMB_CAP_NT_STATUS));
    data = cmAnsiToStr(data, CM_NATIVE_OS, TRUE);  
    data = cmAnsiToStr(data, CM_NATIVE_LANMAN, TRUE);
    pcktSetEnd(packet, data);
    cmPutSUint16(request->andXOffset, cmHtol16((NQ_UINT16)packet->size));

    /* send the packet and receive server response */
    switch (result = exchangeTcpPackets(connection, session->uid, packet))
    {
    case SMB_STATUS_MORE_PROCESSING_REQUIRED:
        /* copy blob received from PDC to server's response */
        response = (CMCifsSessionSetupAndXSSPResponse *)packet->words;
        *pOutBlobLength = cmLtoh16(cmGetSUint16(response->blobLength));
        syMemcpy(pOutBlob, (NQ_BYTE *)(response + 1), *pOutBlobLength);
        session->uid = cmGetSUint16(packet->header->uid); 
        break;
    case NQ_ERR_OK:
        session->setup = TRUE;
        /* copy blob received from PDC to server's response */
        response = (CMCifsSessionSetupAndXSSPResponse *)packet->words;
        *pOutBlobLength = cmLtoh16(cmGetSUint16(response->blobLength));
        syMemcpy(pOutBlob, (NQ_BYTE *)(response + 1), *pOutBlobLength);
    default:
        break;    
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result;
}
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
/*
 *====================================================================
 * PURPOSE: close previously setup session
 *--------------------------------------------------------------------
 * PARAMS:  IN  connection
 *          IN  session
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmCloseSmbSession(
    CMSmbConnection *connection,
    CMSmbSession *session
    )
{
    session->setup = FALSE;
    session->uid = 0;
    session->connection = NULL;
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

/*
 *====================================================================
 * PURPOSE: generate transaction request packet filling it with known data
 *--------------------------------------------------------------------
 * PARAMS:  IN  packet
 *          IN  mailslot name
 *          OUT pointer to the transaction parameters
 *          IN  parameter count
 *          OUT pointer to the transaction data
 *          IN  data count
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

#ifndef UD_NQ_AVOIDDCRESOLUTIONNETBIOS

static void transGenerateRequest(
    CMSmbPacket *packet,
    const NQ_CHAR *mailslot,
    NQ_BYTE **parameters,
    NQ_UINT16 pcount,
    NQ_BYTE **data,
    NQ_UINT16 dcount
    )
{
    CMCifsTransactionRequest *req;
    NQ_BYTE *setup;
    NQ_INT mslen = (NQ_INT)syStrlen(mailslot) + 1;

    pcktClear(packet);
    pcktSetCommand(packet, SMB_COM_TRANSACTION, SMB_TRANSACTION_REQUEST_WORDCOUNT + TRANSACTION_SETUP_COUNT);

    req = (CMCifsTransactionRequest *)packet->words;

    cmPutSUint32(req->timeout, cmHtol32(TRANSACTION_TIMEOUT)); /* referenced as "not used" in the H file */
    req->setupCount = TRANSACTION_SETUP_COUNT;
    req->maxSetupCount = req->setupCount;

    /* setup words */
    setup = (NQ_BYTE *)(req + 1);
    /* fill the setup words {1, 1, 2} - the last two values are ignored according to the "cifslog.txt" */
    cmPutUint16(setup, cmHtol16(1));
    setup += 2;
    cmPutUint16(setup, cmHtol16(1));
    setup += 2;
    cmPutUint16(setup, cmHtol16(2));

    /* set the mail slot name */
    syStrcpy((NQ_CHAR *)packet->bytes->data, mailslot);

    *parameters = pad(packet->bytes->data + mslen, 2);
    *data = pad(*parameters + pcount, 2);

    /* data information */
    cmPutSUint16(req->maxDataCount, cmHtol16((NQ_UINT16)(CIFS_MAX_DATA_SIZE16 - sizeof(CMCifsHeader) - pcount)));
    cmPutSUint16(req->dataCount, cmHtol16(dcount));
    cmPutSUint16(req->dataOffset, cmHtol16((NQ_UINT16)(*data - (NQ_BYTE *)packet->header)));
    cmPutSUint16(req->totalDataCount, cmGetSUint16(req->dataCount));

    /* parameter information */
    cmPutSUint16(req->maxParameterCount, 0);    /* currently zero but may be passed to this function as well */
    cmPutSUint16(req->parameterCount, cmHtol16(pcount));
    cmPutSUint16(req->parameterOffset, cmHtol16((NQ_UINT16)(*parameters - (NQ_BYTE *)packet->header)));
    cmPutSUint16(req->totalParameterCount, cmGetSUint16(req->parameterCount));

    /* determine the packet size */
    pcktSetEnd(packet, *data + dcount);
}

#endif /* UD_NQ_AVOIDDCRESOLUTIONNETBIOS */


/*
 *====================================================================
 * PURPOSE: query given domain for its PDC name and return this name upon success
 *--------------------------------------------------------------------
 * PARAMS:  IN  datagram socket to send the packet through
 *          IN  an empty packet
 *          IN  domain name
 *          OUT PDC name
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
cmGetNetBiosDCName(
    NSSocketHandle socket,         /* datagram socket */
    CMSmbPacket *packet,
    const NQ_CHAR *domain,
    NQ_CHAR *pdc                   /* PDC name upon return */
    )
{
#ifdef UD_NQ_AVOIDDCRESOLUTIONNETBIOS
    return NQ_ERR_GENERAL;
#else /* UD_NQ_AVOIDDCRESOLUTIONNETBIOS */
#define RSPLEN sizeof(MS_RSP_NETLOGONQUERY)   /* this is like strlen() + 1 */
    CMNetBiosNameInfo to;
    NQ_BYTE *parameters;
    NQ_BYTE *data;
    const NQ_CHAR *host = cmNetBiosGetHostNameZeroed();
    NQ_UINT hlen = (NQ_UINT)syStrlen(host) + 1;
    NQ_STATUS status = NQ_ERR_GENERAL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* set PDC NETBIOS name as destination name (DOMAIN<00>) */
    syStrncpy(to.name, domain, CM_NB_NAMELEN);
    cmNetBiosNameFormat(to.name, CM_NB_POSTFIX_DOMAINMASTERBROWSER);
    to.isGroup = FALSE;

    /* prepare transaction packet */
    transGenerateRequest(packet, MS_REQ_NETLOGONQUERY, &parameters, 0, &data,
                         (NQ_UINT16)(sizeof(NQ_BYTE) * 2 + hlen + RSPLEN + 2));
    /* NETLOGON_QUERY request */
    *data++ = OPCODE_NETLOGONQUERY;                                      /* op code */
    *data++ = 0;                                                         /* pad to even address */
    syStrcpy((NQ_CHAR *)data, host);                                     /* sender computer name */
    data += hlen;
    syStrcpy((NQ_CHAR *)data, MS_RSP_NETLOGONQUERY);                     /* reply mailslot name */
    data += RSPLEN;
    cmPutUint16(data, cmHtol16(LM20TOKEN));                              /* LM20 token */

    /* send the packet and get the server response */
    if ((status = exchangeUdpPackets(socket, &to, packet)) == NQ_ERR_OK)
    {
        /* the response comes in a form of transaction request */
        TRC1P("Transaction packet data offset: %d", cmLtoh16(cmGetSUint16(((CMCifsTransactionRequest *)packet->words)->dataOffset)));
        data = (NQ_BYTE *)packet->header + cmLtoh16(cmGetSUint16(((CMCifsTransactionRequest*)packet->words)->dataOffset));

        if (*data == OPCODE_NETLOGONRESPONSE)
        {
            data += 2;                              /* skip opcode and padding */
            syStrncpy(pdc, (NQ_CHAR *)data, CM_NB_NAMELEN + 1);

            TRC2P("Got PDC name for domain %s: %s", domain, (pdc[0] != '\0') ? pdc : "*NOT FOUND*");

            if (pdc[0] == '\0')
                status = NQ_ERR_GENERAL;
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected opcode returned by the PDC");
            status = NQ_ERR_GENERAL;
        }
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "exchangeUdpPackets failed");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
#endif /* UD_NQ_AVOIDDCRESOLUTIONNETBIOS */
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
/*
 *====================================================================
 * PURPOSE: query given domain for its PDC name and return this name upon success
 *--------------------------------------------------------------------
 * PARAMS:  IN  domain name
 *          OUT PDC name
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
cmGetDnsDCName(
    const NQ_CHAR *domain,
    NQ_CHAR *pdc
    )
{
    NQ_CHAR service[CM_DNS_NAMELEN+1] = "_ldap._tcp.dc._msdcs.";
    syStrcat(service, domain);
    return nsDnsGetHostNameByService(service, pdc);
}

#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/*
 *====================================================================
 * PURPOSE: query given domain for its PDC name and return this name upon success
 *--------------------------------------------------------------------
 * PARAMS:  IN  domain name
 *          OUT PDC name
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS cmGetDCNameByDomain(const NQ_CHAR* domain, NQ_CHAR *pdc)
{
    NQ_UINT *t;


    /* check in cache first */
    {
        const CacheEntry * pEntry;   /* cache item */

        pEntry = lookupNameInCache(domain);
        if (NULL != pEntry)
        {
            if (pEntry->exists)
            {
                syStrcpy(pdc, pEntry->pdcName);
                return NQ_SUCCESS;
            }
            else
                return NQ_FAIL;
        }
    }

    for (t = cmGetTransportPriorities(); *t; t++)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
        if (*t == NS_TRANSPORT_NETBIOS)
        {
            NQ_STATIC NQ_BYTE buffer[CM_NB_DATAGRAMBUFFERSIZE];
            NSSocketHandle socket = nsGetCommonDatagramSocket();

            if (socket != NULL)
            {
                CMSmbPacket packet;

                cmPacketAttachBuffer(&packet, buffer);
                if (cmGetNetBiosDCName(socket, &packet, domain, pdc) == NQ_SUCCESS)
                {
                    TRC1P("Found NetBIOS Domain Controller: %s", pdc);
                    addToCache(domain, pdc, TRUE);
                    return NQ_SUCCESS;
                }
                else
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Query for NetBIOS PDC failed");
                }
            }
            else
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Common datagram socket not initialized");
            }
        }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
        if (*t == NS_TRANSPORT_IPV4 || *t == NS_TRANSPORT_IPV6)
        {
            if (cmGetDnsDCName(domain, pdc) == NQ_SUCCESS)
            {
                addToCache(domain, pdc, TRUE);
                TRC1P("Found DNS Domain Controller: %s", pdc);
                return NQ_SUCCESS;
            }
            else
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Query for Dns PDC failed");
            }
        }
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */
    }

    addToCache(domain, pdc, FALSE);
    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: query given domain for its PDC name and return this name upon success
 *--------------------------------------------------------------------
 * PARAMS:  OUT PDC name
 *          OUT domain name (may be NULL)
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS cmGetDCName(NQ_CHAR* pdc, const NQ_CHAR** domainBuffer)
{
    NQ_UINT *t;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (staticData->pdcDiscovered)
    {
        syStrcpy(pdc, staticData->pdcName);
        if (NULL != domainBuffer)
            *domainBuffer = staticData->domainName;
        TRC2P("PDC = %s, Domain = %s", staticData->pdcName, staticData->domainName);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_SUCCESS;
    } 
    
    for (t = cmGetTransportPriorities(); *t; t++)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
        if (*t == NS_TRANSPORT_NETBIOS)
        {
            NQ_STATIC NQ_BYTE buffer[CM_NB_DATAGRAMBUFFERSIZE];
            NSSocketHandle socket = nsGetCommonDatagramSocket();

            if (socket != NULL)
            {
                CMSmbPacket packet;

                cmPacketAttachBuffer(&packet, buffer);
                if (cmGetNetBiosDCName(socket, &packet, cmNetBiosGetDomain()->name, staticData->pdcName) == NQ_SUCCESS)
                {                    
                    staticData->pdcDiscovered = TRUE;
                    staticData->domainName = cmNetBiosGetDomain()->name;                   
                    syStrcpy(pdc, staticData->pdcName);
                    if (NULL != domainBuffer)
                        *domainBuffer = staticData->domainName;
                    TRC2P("Found NetBIOS Domain Controller: %s, Domain: %s", staticData->pdcName, staticData->domainName);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                else
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Query for NetBIOS PDC failed");
                }
            }
            else
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Common datagram socket not initialized");
            }
        }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
        if (*t == NS_TRANSPORT_IPV4 || *t == NS_TRANSPORT_IPV6)
        {
            if ((staticData->domainName = cmGetFullDomainName()) != NULL)
            {
                if (cmGetDnsDCName(staticData->domainName, staticData->pdcName) == NQ_SUCCESS)
                {                  
                    staticData->pdcDiscovered = TRUE;               
                    syStrcpy(pdc, staticData->pdcName);
                    if (NULL != domainBuffer)
                        *domainBuffer = staticData->domainName;
                    TRC2P("Found DNS Domain Controller: %s, Domain: %s", staticData->pdcName, staticData->domainName);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_SUCCESS;
                }
                else
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Query for DNS PDC failed");
                }
            }
        }
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_FAIL;
}
