/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Dispatching Simple (AndX) packets
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSDISPAT_H_
#define _CSDISPAT_H_

#include "nsapi.h"
#include "cslaters.h"
#ifdef UD_NQ_INCLUDESMBCAPTURE
#include "cmcapture.h"
#endif /* UD_NQ_INCLUDESMBCAPTURE */


typedef struct                  /* descriptor for a client socket */
{
    NSSocketHandle socket;      /* socket handle */
#ifdef UD_NQ_INCLUDESMB2    
    NQ_BOOL isSmb2;
#endif /* UD_NQ_INCLUDESMB2 */
    NQ_IPADDRESS ip;            /* ip address on the next side */
    NQ_UINT32 lastActivityTime;   /* time of the last activity on this socket */
#ifdef UD_NQ_USETRANSPORTNETBIOS
    NQ_UINT32 requestTimeout;     /* timestamp for waiting for NBT SESSION REQUEST */
    NQ_BOOL requestExpected;    /* newly connected waits for NBT SESSION REQUEST */
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CMCaptureHeader		captureHdr; /* structure for internal capture */
#endif /* UD_NQ_INCLUDESMBCAPTURE */
}
CSSocketDescriptor;


/* get current socket handle */

NSSocketHandle                  /* socket handle */
csDispatchGetSocket(
    void
    );

/* get current socket IP */

const NQ_IPADDRESS*             /* pointer to socket IP */
csDispatchGetSocketIp(
    void
    );

/* set current socket */

void
csDispatchSetSocket(
    NSSocketHandle newSocket    /* socket handle */
    );

/* dispatcher this module */

NQ_STATUS            /* NQ_SUCCESS or NQ_FAIL */
csDispatchInit(
    void
    );

/* exit dispatcher module */

void
csDispatchExit(
    void
    );

/* responding with error on no resources */

NQ_STATUS
csDispatchErrorNoResources(
    NSSocketHandle socket       /* socket that has an incoming packet */
    );

/* dispatching a request */

NQ_STATUS
csDispatchRequest(
	CSSocketDescriptor * pDescr	/* socket descriptor */
    );

/* check output buffer for enough room */

NQ_UINT32                          /* 0 or error code */
csDispatchCheckSpace(
    const CMCifsHeader* header,
    const NQ_BYTE* pResponse,
    NQ_UINT size
    );

/* save information for a delayed response */

void
csDispatchSaveResponseContext(
    CSLateResponseContext* contextBuffer    /* buffer for context */
    );

/* compose header and calculate command data pointer and size */

NQ_STATUS                             /* NQ_SUCCESS or error code */
csDispatchPrepareLateResponse(
    CSLateResponseContext* context    /* saved context */
    );

/* send a response using saved context */

NQ_STATUS                             /* NQ_SUCCESS or error code */
csDispatchSendLateResponse(
    CSLateResponseContext* context,   /* saved context */
    NQ_UINT32 status,                 /* status to report, zero for success */
    NQ_COUNT dataLength               /* actual command data length */
    );

/* determine type of error code to be returned in the current response */

NQ_BOOL                         /* TRUE when NT error code should be returned */
csDispatchIsNtError(
    void
    );

/* set type of error code to be returned */

void
csDispatchSetNtError(
    NQ_BOOL type            /* TRUE for NT status, FALSE for DOS error */
    );

#ifdef UD_CS_INCLUDEDIRECTTRANSFER

/* set parameters for further Direct Transfer from file to socket */ 
void 
csDispatchDtSet(
	SYFile file,					/* file handle */
	NQ_COUNT count					/* number of bytes */
	);

/* perform Direct Transfer from socket to file */ 
NQ_BOOL								/* TRUE if successful */ 
csDispatchDtFromSocket(
	NSRecvDescr * recvDescr,		/* receive descriptor to use */
	NQ_COUNT required				/* expected number of bytes */
	);

/* perform Direct Transfer from file to socket */ 
NQ_BOOL								/* TRUE if successful */ 
csDispatchDtToSocket(
	NSRecvDescr * recvDescr			/* receive descriptor to use */
	);

/* check if incoming Data Transfer enabled for the current command */ 
NQ_BOOL csDispatchIsDtIn(
	);

/* check if outgoing Data Transfer enabled for the current command */ 
NQ_BOOL csDispatchIsDtOut(
	);

/* decide to discard Direct Transfer */ 
void csDispatchDtDiscard(
	);

/* save DT parameters */
void
csDispatchDtSaveParameters(
	NQ_BYTE * buf,				/* buffer for further discarding */  
	NSRecvDescr * recvDescr		/* receive descriptor */
	);

/* get saved DT count */
NQ_COUNT 
csDispatchDtGetCount(
	);

/* check if DT can be done */
NQ_BOOL
csDispatchDtAvailable(
	);

/* set DT IN flag */
void
csDispatchSetDtIn(NQ_BOOL isOn
	);

/* set DT OUT flag */
void
csDispatchSetDtOut(NQ_BOOL isOn
	);

#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

#ifdef UD_NQ_INCLUDESMBCAPTURE
CSSocketDescriptor * csGetClientSocketDescriptorBySocket(NSSocketHandle socket);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
/*
    Command processors
    ------------------
    Function prototypes for command processors. Each function is responsible for one command.
    The following typedef (for consideration only) designates such function's format
 */

typedef
NQ_UINT32 (*CSCommandFunction)(        /* returns error code o 0 on success */
    NQ_BYTE* pRequest,                 /* pointer to the command structure in the packet */
    CMCifsHeader* pHeaderOut,       /* outgoing packet header */
    NQ_BYTE** pResponse                /* Double pointer for generating a response. The function
                                       should increase this pointer to the 1t byte after the
                                       new response. */
    );

NQ_UINT32 csComCreateDirectory(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComDeleteDirectory(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComOpen(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComCreate(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComClose(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComFlush(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComDelete(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComRename(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComQueryInformation(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComSetInformation(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComRead(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComWrite(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComWriteAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComCreateNew(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComCheckDirectory(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComSeek(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComSetInformation2(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComQueryInformation2(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComLockingAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComTransaction(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComOpenAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComReadAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComTransaction2(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComFindClose2(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComTreeConnect(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComTreeDisconnect(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComNegotiate(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComSessionSetupAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComLogoffAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComTreeConnectAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComQueryInformationDisk(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComSearch(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComNtCreateAndX(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComNtTransaction(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComNtCancel(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComProcessExit(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComEcho(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
#ifdef UD_CS_INCLUDERPC_SPOOLSS
NQ_UINT32 csComOpenPrintFile(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
NQ_UINT32 csComClosePrintFile(NQ_BYTE* , CMCifsHeader* , NQ_BYTE** pResponse);
#endif

#endif  /* _CSDISPAT_H_ */


