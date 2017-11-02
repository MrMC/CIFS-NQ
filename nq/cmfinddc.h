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

#ifndef _CMFINDDC_H_
#define _CMFINDDC_H_
#include "nsapi.h"
/*
    data structures
*/

/* TCP connection for SMB packet exchange */

typedef struct {
    NSSocketHandle    socket;
    CMNetBiosNameInfo host;
    NQ_IPADDRESS      ip;
    NQ_BOOL           established;
    NQ_BOOL           negotiated;
    NQ_BOOL           unicode;
    NQ_UINT32         key;
    NQ_UINT32         sequence;
    NQ_BYTE           encryption[SMB_ENCRYPTION_LENGTH];
/*    NQ_BYTE           mac[16];
    NQ_BYTE           response[24];*/
}
CMSmbConnection;

/* SMB session over established TCP connection */

typedef struct {
    CMSmbConnection *connection;
    NQ_BOOL          setup;
    NQ_UINT16        uid;
}
CMSmbSession;

/* SMB packet for data exchange over TCP and UDP */

typedef struct {
    NQ_BYTE         *buffer;
    CMCifsHeader    *header;
    CMCifsWordBlock *words;
    CMCifsByteBlock *bytes;
    NQ_UINT          size;
}
CMSmbPacket;

/* initialize find DC resources */

NQ_STATUS
cmFindDCInit(
    void
    );
    
/* release find DC resources */

void
cmFindDCExit(
    void
    );
    
/* attach NETBIOS buffer to a packet */

void
cmPacketAttachBuffer(
    CMSmbPacket *packet,
    NQ_BYTE *buffer
    );

/* returns the list of transports by their priorities */

NQ_UINT*
cmGetTransportPriorities(
    void
    );

/* establish negotiated SMB connection with given server */

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
    );

/* close connection */

void
cmCloseConnection(
    CMSmbConnection *connection
    );

/* close previously setup session */

void
cmCloseSmbSession(
    CMSmbConnection *connection,
    CMSmbSession *session
    );

/* query given NetBIOS domain for its PDC name and return this name upon success */

NQ_STATUS
cmGetNetBiosDCName(
    NSSocketHandle socket,         /* datagram socket */
    CMSmbPacket *packet,
    const NQ_CHAR *domain,
    NQ_CHAR *pdc                   /* PDC name upon return */
    );

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
/* query given domain for its PDC name and return this name upon success */

NQ_STATUS
cmGetDnsDCName(
    const NQ_CHAR *domain,
    NQ_CHAR *pdc                   /* PDC name upon return */
    );

#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/* query given domain (NetBIOS or DNS) for its PDC name and return server name */

NQ_STATUS
cmGetDCName(
    NQ_CHAR* pdc,                   /* PDC name upon return */
    const NQ_CHAR** domainBuffer    /* domain name (may be NULL) */
    );

NQ_STATUS
cmGetDCNameByDomain(
    const NQ_CHAR *domain,         /* domain name to find PDC for */
    NQ_CHAR *pdc                   /* PDC name upon return */
    );

/* perform session setup */

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
    );

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
/* perform session setup with extended security */

NQ_UINT32
cmSetupSessionExtendedSecurity(
    CMSmbConnection *connection,
    CMSmbSession *session,
    CMSmbPacket *packet,
    const NQ_BYTE *inBlob,
    const NQ_UINT16 inBlobLength,
    NQ_BYTE* pOutBlob,
    NQ_COUNT* pOutBlobLength
    );    
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */

#endif
