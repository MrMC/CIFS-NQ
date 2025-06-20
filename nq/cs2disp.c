/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 command dispatcher
 *--------------------------------------------------------------------
 * MODULE        : CS
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 02-Dec-2008
 ********************************************************************/

#include "csnotify.h"
#include "cs2disp.h"
#include "csdispat.h"
#include "nssocket.h"
#ifdef UD_CS_MESSAGESIGNINGPOLICY
#include "cssignin.h"
#endif

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

typedef struct
{
    NQ_BYTE responseBuffer[CM_NB_DATAGRAMBUFFERSIZE];/* buffer for late response */
    NSSocketHandle savedSocket;       /* handle of the socket over which the current */
    CSFid quickFid;                   /* saved fid for compounded requests */
    CMSmb2Header* header;             /* pointer to the current header */
    NQ_BOOL	encrypedPacket;
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/*
 * SMB2 command handler
 * In terms of SMB2:
 * CSSession -> connection
 * CSUser    -> session
 * CSTree    -> tree
 */
typedef NQ_UINT32 (*Smb2CommandHandler)(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer);

/* SMB2 command table entry */
typedef struct
{
/*  NQ CHAR * name; */ 
    Smb2CommandHandler handler;
    NQ_UINT16 size;
    NQ_UINT16 flags;
}
Entry;

#define FLAG_NOCONNECTION   0x0001
#define FLAG_NOSESSION      0x0002
#define FLAG_NOTREE         0x0004
#define FLAG_DTIN           0x0008  /* incoming Direct Transfer */
#define FLAG_DTOUT          0x0010  /* outgoing Direct Transfer */

/*
 * SMB2 command table
 */
static const Entry _entries[] = {
    /* SMB2_COM_NEGOTIATE       0x0000 */  {/*"NEGOTIATE",*/       csSmb2OnNegotiate,      36, FLAG_NOCONNECTION | FLAG_NOSESSION | FLAG_NOTREE},
    /* SMB2_COM_SESSION_SETUP   0x0001 */  {/*"SESSION_SETUP",*/   csSmb2OnSessionSetup,   25, FLAG_NOSESSION | FLAG_NOTREE}, 
    /* SMB2_COM_LOGOFF          0x0002 */  {/*"LOGOFF",*/          csSmb2OnLogoff,          4, FLAG_NOTREE},
    /* SMB2_COM_TREE_CONNECT    0x0003 */  {/*"TREE_CONNECT",*/    csSmb2OnTreeConnect,     9, FLAG_NOTREE},
    /* SMB2_COM_TREE_DISCONNECT 0x0004 */  {/*"TREE_DISCONNECT",*/ csSmb2OnTreeDisconnect,  4, 0},
    /* SMB2_COM_CREATE          0x0005 */  {/*"CREATE",*/          csSmb2OnCreate,         57, 0},
    /* SMB2_COM_CLOSE           0x0006 */  {/*"CLOSE",*/           csSmb2OnClose,          24, 0},
    /* SMB2_COM_FLUSH           0x0007 */  {/*"FLUSH",*/           csSmb2OnFlush,          24, 0},
    /* SMB2_COM_READ            0x0008 */  {/*"READ",*/            csSmb2OnRead,           49, FLAG_DTOUT},
    /* SMB2_COM_WRITE           0x0009 */  {/*"WRITE",*/           csSmb2OnWrite,          49, FLAG_DTIN},
    /* SMB2_COM_LOCK            0x000A */  {/*"LOCK",*/            csSmb2OnLock,           48, 0},
    /* SMB2_COM_IOCTL           0x000B */  {/*"IOCTL",*/           csSmb2OnIoctl,          57, 0},
    /* SMB2_COM_CANCEL          0x000C */  {/*"CANCEL",*/          csSmb2OnCancel,          4, 0},
    /* SMB2_COM_ECHO            0x000D */  {/*"ECHO",*/            csSmb2OnEcho,            4, FLAG_NOSESSION | FLAG_NOTREE},
    /* SMB2_COM_QUERY_DIRECTORY 0x000E */  {/*"QUERY_DIRECTORY",*/ csSmb2OnQueryDirectory, 33, 0},
    /* SMB2_COM_CHANGE_NOTIFY   0x000F */  {/*"CHANGE_NOTIFY",*/   csSmb2OnChangeNotify,   32, 0},
    /* SMB2_COM_QUERY_INFO      0x0010 */  {/*"QUERY_INFO",*/      csSmb2OnQueryInfo,      41, 0},
    /* SMB2_COM_SET_INFO        0x0011 */  {/*"SET_INFO",*/        csSmb2OnSetInfo,        33, 0},
    /* SMB2_COM_OPLOCK_BREAK    0x0012 */  {/*"OPLOCK_BREAK",*/    csSmb2OnOplockBreak,    24, 0},
};

static void releaseCallback(const NQ_BYTE* buffer)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    nsPutBuffer((NQ_BYTE*)buffer);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void writeErrorResponseData(CMBufferWriter *writer)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    cmBufferWriteUint16(writer, 9);  /* size */
    cmBufferWriteUint16(writer, 0);  /* reserved */
    cmBufferWriteUint32(writer, 0);  /* byte count */
    cmBufferWriteByte(writer, 0);    /* 1 byte of data (required if ByteCount == 0) */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void setQuickFid(CSFid* fid)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    staticData->quickFid = *fid;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);   
}

static void getQuickFid(CSFid* fid)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    *fid = staticData->quickFid;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}    

static void resetQuickFid()
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    staticData->quickFid = CS_ILLEGALID;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*====================================================================
 * PURPOSE: Parse FID
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to fid
 *
 * RETURNS: none
 *
 * NOTES:   According to fid value save it (for usage of further requests 
 *          in the same packet) or get previously saved one.
 *====================================================================
 */
void cs2ParseFid(CSFid* fid)
{ 
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    (*fid == CS_ILLEGALID) ? getQuickFid(fid) : setQuickFid(fid);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}


/*====================================================================
 * PURPOSE: initialize resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
cs2DispatchInit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */
    staticData->encrypedPacket = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: release resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
cs2DispatchExit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*====================================================================
 * PURPOSE: SMB2 async ID generator
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for next async ID
 *
 * RETURNS: None
 *
 * NOTES:   
 *====================================================================
 */

void cs2GenerateNextAsyncId(NQ_UINT64 * id)
{
    static NQ_UINT32 nextAsyncId = 1;
    nextAsyncId++;
    if (0 == nextAsyncId)
        nextAsyncId = 1;
    id->high = 0;
    id->low = nextAsyncId;
}

/*====================================================================
 * PURPOSE: Get current command header
 *--------------------------------------------------------------------
 * PARAMS:  None 
 *
 * RETURNS: Pointer to the header
 *
 * NOTES:   This function should be called only inside the csSmb2DispatchRequest()
 *          processing
 *====================================================================
 */

CMSmb2Header *
cs2DispatchGetCurrentHeader(
    void
    )
{
    return staticData->header;
}

/*====================================================================
 * PURPOSE: SMB2 command dispatcher
 *--------------------------------------------------------------------
 * PARAMS:  IN receive descriptor 
 *          IN request - pointer to the incoming request packet
 *          IN length -  incoming packet length without four bytes of signature  
 *
 * RETURNS: TRUE on success or FALSE on any error
 *
 * NOTES:   The buffer passed from the outside will be released by caller!
 *          four bytes of signature are already read through the descriptor
 *====================================================================
 */

NQ_BOOL 
csSmb2DispatchRequest(
    NSRecvDescr * recvDescr, 
    NQ_BYTE * request, 
    NQ_COUNT length
    )
{
    CMSmb2Header in, out;
    CMBufferReader reader;
    CMBufferWriter primary, data;
    NQ_INT written, sent;
    NQ_BYTE *response;
    NQ_UINT32 result;
    NQ_BYTE * pBuf = request + 4;
    NQ_BOOL isFirstInChain = TRUE;
    NQ_COUNT packetLen;
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    NQ_COUNT dataLength;
    CMBufferWriter packet;
#endif
    CSUser *session = NULL;
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor * sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    NQ_BOOL 	encryptedPacket = FALSE;
    CSSession *connection = csGetSessionBySocket();
#ifdef UD_NQ_INCLUDESMB3
    static NQ_BYTE ctxBuff[SHA512_CTXSIZE];
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "recvDescr:%p request:%p length:%d", recvDescr, request, length);

    if (connection == NULL)
		connection = csGetNewSession();

    staticData->savedSocket = recvDescr->socket;
    
#ifdef UD_NQ_INCLUDESMBCAPTURE
    sockDescr = csGetClientSocketDescriptorBySocket(staticData->savedSocket);
#endif /* UD_NQ_INCLUDESMBCAPTURE */

    /* always respond NT STATUS */
    csDispatchSetNtError(TRUE);
#ifdef UD_NQ_INCLUDESMB3
    if (syMemcmp(request , cmSmb2TrnsfrmHdrProtocolId , sizeof(cmSmb2TrnsfrmHdrProtocolId)) == 0)
    {
    	NQ_BOOL res;
		
    	encryptedPacket = TRUE;
    	res = cs2TransformHeaderDecrypt( recvDescr , request , length);
    	if (res)
    	{
    		pBuf = request + SMB2_TRANSFORMHEADER_SIZE + 4;
    		length =  length - SMB2_TRANSFORMHEADER_SIZE + 4;
    	}
    	else
    	{
			LOGERR(CM_TRC_LEVEL_ERROR, "Encrypted Packet Signature doesn't match");
			LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
			return NQ_FAIL;
    	}
    }
#endif /* UD_NQ_INCLUDESMB3 */
    staticData->encrypedPacket = encryptedPacket;
    /* according to nsGetBuffer() implementation its return value can not be NULL */
    response = nsGetBuffer();

    if (!encryptedPacket)
    {
		if (NQ_FAIL == nsRecvIntoBuffer(recvDescr, pBuf, 62)) /* read the rest of the header + StructureSize */
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Error reading from socket");
			LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
			return NQ_FAIL;
		}
    }
    else
    {
    	syMemset(response , 0 , UD_NS_BUFFERSIZE);
    	response += SMB2_TRANSFORMHEADER_SIZE;
    }
    
#ifdef UD_NQ_INCLUDESMBCAPTURE
    if (!encryptedPacket)
    {
    	cmCapturePacketWritePacket(request + 4, 62);
    }
    else
    {
    	cmCapturePacketWritePacket(pBuf - 4 , length);
    	cmCapturePacketWriteEnd();
    }
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    cmBufferReaderInit(&reader, !encryptedPacket ? request : pBuf - 4 ,length);
    cmBufferWriterInit(&primary, nsSkipHeader(recvDescr->socket, response), UD_NS_BUFFERSIZE);

#ifdef UD_CS_MESSAGESIGNINGPOLICY
    cmBufferWriterBranch(&primary, &packet, 0);
    dataLength = length + 4;
    TRC("dataLength %d", dataLength);
#endif

    pBuf += 62;
    length -= 62;

    resetQuickFid();    /* reset quick fid for next packet */

    do
    {
        NQ_UINT16 size;
        NQ_INT msgLen;

        /* buffer overrun check: header + 2 bytes for payload size */
        if (cmBufferReaderGetRemaining(&reader) < SMB2_HEADERSIZE - 2) /* minus 4 bytes already read before */
        {
            nsPutBuffer(response);
            LOGERR(CM_TRC_LEVEL_ERROR, "insufficient request length %d", cmBufferReaderGetRemaining(&reader));
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
            return FALSE;
        }

        /* read request packet header */    
        cmSmb2HeaderRead(&in, &reader);
        staticData->header = &in;
        /* read payload size */
        cmBufferReadUint16(&reader, &size);

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Request: command=%d, mid=%u/%u, pid=0x%08x, sid=0x%08x, tid=0x%08x, credits=%d", in.command, in.mid.high, in.mid.low, in.pid, in.sid.low, in.tid, in.credits);
        
        /* command range check */
        if (in.command < CM_ARRAY_SIZE(_entries))
        {
            NQ_UINT creditsGranted;
            const Entry *e = &_entries[in.command];            

        /* try DT IN */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
        csDispatchSetDtOut(FALSE);
        csDispatchSetDtIn(FALSE);
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
        if (isFirstInChain)
        {
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
            if ((_entries[in.command].flags & FLAG_DTIN) 
                    && in.next == 0 
#ifdef UD_CS_MESSAGESIGNINGPOLICY            
                    && ((in.flags & SMB2_FLAG_SIGNED) == 0)
#endif /* UD_CS_MESSAGESIGNINGPOLICY */            
					&& !encryptedPacket
            )
            { 
                /* use DirectTransfer - read according to word count */
                csDispatchSetDtIn(TRUE);
                msgLen = (NQ_INT)nsRecvIntoBuffer(recvDescr, pBuf, (NQ_COUNT)(size - 3)); /* read command structure */
                csDispatchDtSaveParameters(pBuf + size - 3, recvDescr);
            }
            else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
            {
                msgLen = (!encryptedPacket) ? nsRecvIntoBuffer(recvDescr, pBuf, length) : (NQ_INT)length; /* read the rest of the packet */
            }
            if (msgLen == NQ_FAIL)
            {
                nsPutBuffer(response);
                LOGERR(CM_TRC_LEVEL_ERROR, "error receiving command");
                LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
                return FALSE;
            }

#ifdef UD_NQ_INCLUDESMBCAPTURE
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
            if (e->flags & FLAG_DTIN && !encryptedPacket)
            {
            	NQ_BYTE *	tempBuf;
            	NQ_UINT32	dataLen;
            	NQ_UINT16	offset;
            	CMBufferReader	reader;

            	cmBufferReaderInit(&reader , pBuf , (NQ_COUNT)(size - 3));
            	cmBufferReadUint16(&reader , &offset);
            	cmBufferReadUint32(&reader , &dataLen);

            	if (offset > (size - 1 + SMB2_HEADERSIZE  ) )
            	{
            		dataLen += (NQ_UINT32)(offset - (size - 1 + SMB2_HEADERSIZE ));
            	}

            	tempBuf = (NQ_BYTE *)cmMemoryAllocate(dataLen);
            	syMemset(tempBuf , 0 , dataLen);

            	cmCapturePacketWritePacket(pBuf, (NQ_UINT)size - 3);
            	cmCapturePacketWritePacket(tempBuf, (NQ_UINT)dataLen);
				cmCapturePacketWriteEnd();

            	cmMemoryFree(tempBuf);
            }
            else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
            {
            	if (!encryptedPacket)
				{
					cmCapturePacketWritePacket(pBuf, (NQ_UINT)msgLen);
					cmCapturePacketWriteEnd();
				}
            }
#endif /* UD_NQ_INCLUDESMBCAPTURE */
        }
        
      /* try DT OUT */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
        if (isFirstInChain &&
                (_entries[in.command].flags & FLAG_DTOUT) && 
                in.next == 0 
#ifdef UD_CS_MESSAGESIGNINGPOLICY            
                && ((in.flags & SMB2_FLAG_SIGNED) == 0)
#endif /* UD_CS_MESSAGESIGNINGPOLICY */            
				&& !encryptedPacket
        )
        { 
            /* use DirectTransfer - prepare socket */
            syDtStartPacket(((SocketSlot*)recvDescr->socket)->socket);
            csDispatchSetDtOut(TRUE);
        }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

        /* setup data writer */
        cmBufferWriterBranch(&primary, &data, SMB2_HEADERSIZE);
       
        if (connection != NULL)
        /* connection == NULL can happen only if we reached max connections */		
        {
            /* option: Add an additional size column "min" to the command table. For all commands except SESSION_SETUP it will be
                       equal to size. For SESSION_SETUP it should be 21 (in case there is no security blob).
                       In the following line add "&& cmBufferReaderGetRemaining(&data) >= e->size2" to check for buffer overrun in
                       a static part of a command. */

        	/* setup response header
			 * we calculate number of credits */
			out = in;
			if (in.command == SMB2_CMD_NEGOTIATE)
			{
				creditsGranted = 1;
			}
			else
			{
				creditsGranted = connection->credits > in.credits? in.credits : connection->credits;
				connection->creditsToGrant = creditsGranted;
			}

			cmSmb2HeaderSetForResponse(&out, &primary, (NQ_UINT16)creditsGranted);

			connection->credits -=  creditsGranted - 1;

            if (size == e->size)
            {
                NQ_BOOL nosess = (e->flags & FLAG_NOSESSION) != 0;
                
                session = nosess ? NULL : csGetUserByUid((CSUid)sessionIdToUid(in.sid.low));
                if (NULL != session)
                { 
                    /* renew session timestamp */
                    csRenewUserTimeStamp(session);
                }      

                if (nosess || session != NULL)
                {
                    NQ_BOOL notree = (e->flags & FLAG_NOTREE) != 0; 
                    NQ_BOOL async = (in.flags & SMB2_FLAG_ASYNC_COMMAND) != 0;
                    CSTree *tree = (notree || async) ? NULL : csGetTreeByTid((CSTid)in.tid);

                    if (notree || async || tree != NULL)
                    {
#ifdef UD_CS_MESSAGESIGNINGPOLICY
#ifdef UD_NQ_INCLUDESMB3						
                   	    if (connection->dialect >= CS_DIALECT_SMB30)
					    {
						    if (!encryptedPacket && !csCheckMessageSignatureSMB3(session, (NQ_BYTE*)in._start , (NQ_COUNT)(in.next == 0 ? dataLength : in.next) , in.flags))
                    	    {								
                    		    LOGERR(CM_TRC_LEVEL_ERROR, "incoming signature doesn't match");
                    		    out.status = result = SMB_STATUS_ACCESS_DENIED;
                    		    cmBufferWriterReset(&data);
							    writeErrorResponseData(&data);
							    cmSmb2HeaderWrite(&out, &primary);
							    cmBufferWriterSync(&primary, &data);
							    dataLength -= (NQ_COUNT)in.next;
							    break;
                    	    }
                        }
                        /* check incoming message signature */
                   	    else
#endif /* UD_NQ_INCLUDESMB3 */
                   	    {
						    if (!csCheckMessageSignatureSMB2(session, (NQ_BYTE*)in._start, (NQ_COUNT)(in.next == 0 ? dataLength : in.next), in.flags))
							{
								LOGERR(CM_TRC_LEVEL_ERROR, "incoming signature doesn't match");
								out.status = result = SMB_STATUS_ACCESS_DENIED;
								cmBufferWriterReset(&data);
								writeErrorResponseData(&data);
								cmSmb2HeaderWrite(&out, &primary);
								cmBufferWriterSync(&primary, &data);
								dataLength -= (NQ_COUNT)in.next;
								break;
							}
                   	    }

                        dataLength -= (NQ_COUNT)in.next;                    
#endif /* UD_CS_MESSAGESIGNINGPOLICY */						

#ifdef UD_NQ_INCLUDESMB3
#ifndef UD_CS_ALLOW_NONENCRYPTED_ACCESS_TO_ENCRYPTED_SHARE
                        if (!encryptedPacket && ((session && csIsServerEncrypted()) || (tree && tree->share->isEncrypted)))
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "%s requires encrypted access and received packet is not encrypted.", csIsServerEncrypted() ? "server" : "share");
							out.status = result = SMB_STATUS_ACCESS_DENIED;
                    		cmBufferWriterReset(&data);
							writeErrorResponseData(&data);
							cmSmb2HeaderWrite(&out, &primary);
							cmBufferWriterSync(&primary, &data);
							dataLength -= (NQ_COUNT)in.next;
							break;
						}
#endif /* UD_CS_ALLOW_NONENCRYPTED_ACCESS_TO_ENCRYPTED_SHARE */
#endif /* UD_NQ_INCLUDESMB3 */

                        /* process request and set the status */
                        result = e->handler ? e->handler(&in, &out, &reader, connection, session, tree, &data) : SMB_STATUS_NOT_IMPLEMENTED;
                        switch (result)
                        {
                            case SMB_STATUS_DISCONNECT:
                                nsPutBuffer(response);
                                LOGERR(CM_TRC_LEVEL_ERROR, "command handler returned status DISCONNECT");
                                LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
                                return FALSE;
                            case SMB_STATUS_NORESPONSE:
                                nsPutBuffer(response);
                                LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
                                return TRUE;
                        }
                    }
                    else
                    {
                        result = SMB_STATUS_NETWORK_NAME_DELETED;

                        LOGERR(CM_TRC_LEVEL_ERROR, "tree not found");
                    }
                }
                else
                {
                    result = SMB_STATUS_USER_SESSION_DELETED;

                    LOGERR(CM_TRC_LEVEL_ERROR, "session not found");
                }
            }
            else
            {
                result = SMB_STATUS_INVALID_PARAMETER;

                LOGERR(CM_TRC_LEVEL_ERROR, "command structure size is %u, expected %u", size, e->size);
            }

            /* on error write error response data part */
            if (result != SMB_STATUS_CUSTOM_ERROR_RESPONSE)
            {
                out.status = result;
            
                if (out.status != 0 && out.status != SMB_STATUS_MORE_PROCESSING_REQUIRED)
                {
                    cmBufferWriterReset(&data);
                    writeErrorResponseData(&data);
                }
            }

            /* if compounded request align writer and advance reader properly */
            if (in.next > 0)
            {
                cmSmb2HeaderAlignWriter(&out, &data, 8);
                out.next = cmSmb2HeaderGetWriterOffset(&out, &data);
            }

            /* write response header (including processing status) */
            cmSmb2HeaderWrite(&out, &primary);

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Response: command=%d, mid=%u/%u, pid=0x%08x, sid=0x%08x, tid=0x%08x, status=%x", out.command, out.mid.high, out.mid.low, out.pid, out.sid.low, out.tid, out.status);

            /* prepare main writer for the next header */
            cmBufferWriterSync(&primary, &data);

#ifdef UD_CS_MESSAGESIGNINGPOLICY
            cmBufferWriterSync(&packet, &primary);
#ifdef UD_NQ_INCLUDESMB3
            /* sign message if dialect 3.0 or above and
            if dialect 3.1.1 and command was session setup with success - signing required */
#ifdef UD_NQ_INCLUDESMB311
            if (in.command == SMB2_CMD_SESSIONSETUP && connection->dialect == CS_DIALECT_SMB311 && result == NQ_SUCCESS)
            	*(packet.origin + 16) |= SMB2_FLAG_SIGNED;
#endif
               
            if (connection->dialect >= CS_DIALECT_SMB30)
            {   
			    if (!encryptedPacket)
                    csCreateMessageSignatureSMB3(out.sid.low, cmBufferWriterGetStart(&packet), cmBufferWriterGetDataCount(&packet));
            }
            else
#endif /* UD_NQ_INCLUDESMB3 */
            {
                csCreateMessageSignatureSMB2(out.sid.low, cmBufferWriterGetStart(&packet), cmBufferWriterGetDataCount(&packet));
            }
            cmBufferWriterBranch(&primary, &packet, 0);

#endif /* UD_CS_MESSAGESIGNINGPOLICY */
        }
        else
        {
            nsPutBuffer(response);
            LOGERR(CM_TRC_LEVEL_ERROR, "connection not found");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
            return FALSE;
        }
        }
        else
        {
            nsPutBuffer(response);
            LOGERR(CM_TRC_LEVEL_ERROR, "invalid command code %u", in.command);
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL);   
            return FALSE;
        }
        isFirstInChain = FALSE;
    }
    while (cmSmb2HeaderShiftNext(&in, &reader));

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtIn())
    {
        if (!csDispatchDtFromSocket(recvDescr, csDispatchDtGetCount()))
        {
            nsPutBuffer(response);
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
            return NQ_SUCCESS;
        }
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

    nsEndRecvIntoBuffer(recvDescr);

    /* send the response */
    written = (NQ_INT)cmBufferWriterGetDataCount(&primary);
    
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "sending response packet: size=%d", written);

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtOut() && csDispatchDtAvailable())
    {
        packetLen = (NQ_COUNT)((NQ_COUNT)written + csDispatchDtGetCount());
    }
    else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    {
        packetLen = (NQ_COUNT)written;
    }

#ifdef UD_NQ_INCLUDESMBCAPTURE
    sockDescr->captureHdr.receiving = FALSE;
    cmCapturePacketWriteStart(&sockDescr->captureHdr , packetLen);
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtOut() && csDispatchDtAvailable())
    {
    	NQ_BYTE *	tempBuf;
    	NQ_COUNT	len;

    	len = csDispatchDtGetCount();
    	tempBuf = (NQ_BYTE *)cmMemoryAllocate(len);
    	syMemset(tempBuf , 0 , len);

    	cmCapturePacketWritePacket(response + 4 , (NQ_UINT)written);
    	cmCapturePacketWritePacket(tempBuf , len);

    	cmMemoryFree(tempBuf);
    }
    else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    {
    	cmCapturePacketWritePacket(response + 4 , packetLen);
    }
    cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */

#ifdef UD_NQ_INCLUDESMB3
    /* calculate hash on response packets. request calculated above */
    if (connection->dialect == CS_DIALECT_SMB311)
    {

    	if (out.command == SMB2_CMD_NEGOTIATE && connection->preauthIntegOn)
    	{
    		cmSmb311CalcMessagesHash(primary.origin, (NQ_UINT)(written), connection->preauthIntegHashVal, ctxBuff);
    		connection->preauthIntegOn = FALSE;
    	}
		if (out.command == SMB2_CMD_SESSIONSETUP)
		{
			CSUser *	pUser = NULL;

			pUser = csGetUserByUid((CSUid)sessionIdToUid(out.sid.low));
			if (pUser != NULL && pUser->preauthIntegOn)
			{
				cmSmb311CalcMessagesHash(primary.origin, (NQ_UINT)(written), pUser->preauthIntegHashVal, ctxBuff);
			}
		}
    }

    if (encryptedPacket)
    {
    	NQ_INT yes = SMB2_TRANSFORMHEADER_SIZE;

    	yes -= nsSkipHeader(recvDescr->socket, response) == response ? 0 : 4;
    	cs2TransformHeaderEncrypt(NULL, response - yes, (NQ_COUNT)written);
    	response -= SMB2_TRANSFORMHEADER_SIZE;
    	written += SMB2_TRANSFORMHEADER_SIZE;
    	packetLen = (NQ_COUNT)written;
    }
#endif /* UD_NQ_INCLUDESMB3 */
    written = (NQ_INT)nsPrepareNBBuffer(response, (NQ_UINT)packetLen, (NQ_UINT)written);
	if (0 == written)
	{
        /* error */
        LOGERR(CM_TRC_LEVEL_ERROR, "prepare buffer failed");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
	}

    if ((sent = nsSendFromBuffer(
                    staticData->savedSocket, 
                    response, 
                    (NQ_UINT)packetLen, 
                    (NQ_UINT)written, 
                    &releaseCallback)
        ) != written)
    {
        /* error */
        LOGERR(CM_TRC_LEVEL_ERROR, "sending response packet failed: size=%d, sent=%d", written, sent);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
    }

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    if (csDispatchIsDtOut())
    {
        /* Transfer bytes from file to socket */
        if (!csDispatchDtToSocket(recvDescr))
        {
            TRCE();
            return NQ_SUCCESS;
        }
        syDtEndPacket(((SocketSlot*)recvDescr->socket)->socket);
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: save information for a delayed response
 *--------------------------------------------------------------------
 * PARAMS:  OUT pointer to the buffer for response context
 *          IN pointer to the interim response header
 *          IN expected length of the response command
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
cs2DispatchSaveResponseContext(
    CSLateResponseContext * contextBuffer,
    const CMSmb2Header * header
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);    
    contextBuffer->prot.smb2.flags = header->flags;
    contextBuffer->prot.smb2.tid = header->tid;
    contextBuffer->prot.smb2.sid = header->sid;
    contextBuffer->prot.smb2.mid = header->mid;
    contextBuffer->prot.smb2.pid = header->pid;
    contextBuffer->prot.smb2.command = (NQ_BYTE)header->command;
    contextBuffer->prot.smb2.aid = header->aid;
    contextBuffer->socket = staticData->savedSocket;
#ifdef UD_NQ_INCLUDESMB3
    contextBuffer->doEncrypt = staticData->encrypedPacket;
#endif
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: get new context for this file - for late responses on file requests.
 *--------------------------------------------------------------------
 * PARAMS:  pFile - pointer to a file descriptor
 * 
 * RETURNS: pointer to context
 *
 * NOTES:
 *====================================================================
 */
/*
CSLateResponseContext
cs2DispatchGetFreeResponseContext(
	CSFile * pFile)
{
    NQ_COUNT i;
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    for (i = 0, i < CM_RPC_MAXNUMOF_PENDINGNOTIFYCTXS; ++i)
    {
        if (pFile->notifyContext[i].status == 0)
            return &(pFile->notifyContext[i]);
    }
    return NULL;
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}
*/
/*
 *====================================================================
 * PURPOSE: compose header and calculate command data pointer and size
 *--------------------------------------------------------------------
 * PARAMS:  IN saved context
 *          IN status to return 
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   prepares CIFS header
 *====================================================================
 */

NQ_STATUS
cs2DispatchPrepareLateResponse(
    CSLateResponseContext* context,
    NQ_UINT32 status
    )
{
    CMBufferWriter writer;  /* header writer */
    CMSmb2Header out;       /* header data */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    CSUser *pUser;
    CSSession *pSession;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    cmBufferWriterInit(&writer, nsSkipHeader(context->socket, staticData->responseBuffer), UD_NS_BUFFERSIZE);
    cmSmb2HeaderInitForResponse(&out, &writer, 1);
    out.command = context->prot.smb2.command;
    out.mid = context->prot.smb2.mid;
    out.pid = context->prot.smb2.pid;
    out.sid = context->prot.smb2.sid;
    out.tid = context->prot.smb2.tid;
    out.aid = context->prot.smb2.aid;
    out.flags = SMB2_FLAG_SERVER_TO_REDIR | SMB2_FLAG_ASYNC_COMMAND;
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    if (((pUser = csGetUserByUid((CSUid)sessionIdToUid(out.sid.low))) && (pSession = csGetSessionById(pUser->session)) && pSession->signingOn) ||
       (context->prot.smb2.flags & SMB2_FLAG_SIGNED))
        out.flags |= SMB2_FLAG_SIGNED;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
    out.status = status;
    cmSmb2HeaderWrite(&out, &writer);
    context->commandData = writer.current;
    context->commandDataSize = writer.length - (NQ_COUNT)(writer.current - writer.origin);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: send a response using saved context
 *--------------------------------------------------------------------
 * PARAMS:  IN saved context
 *          IN command data length
 *
 * RETURNS: TRUE for success
 *====================================================================
 */

NQ_BOOL
cs2DispatchSendLateResponse(
    CSLateResponseContext* context,
    NQ_COUNT dataLength
    )
{
    CSSession * pSession;
    NQ_COUNT packetLen;  /* packet length, no NB header */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor *	sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */
#ifdef UD_NQ_INCLUDESMB3
    NQ_BYTE	encryptBuf[CM_NB_DATAGRAMBUFFERSIZE + SMB2_TRANSFORMHEADER_SIZE];

    NQ_BOOL	isEncrypted = context->doEncrypt;
#endif
    
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "context:%p dataLength:%d", context, dataLength);

    pSession = csGetSessionBySpecificSocket(context->socket);
    packetLen = (NQ_COUNT)(context->commandData + dataLength - nsSkipHeader(context->socket, staticData->responseBuffer));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "packetLen:%d", packetLen);

#ifdef UD_CS_MESSAGESIGNINGPOLICY
    {
		CMBufferReader	reader;
		CMBufferWriter	writer;
		CMSmb2Header hdr;

		cmBufferReaderInit(&reader , nsSkipHeader(context->socket, staticData->responseBuffer) , 64);
		cmSmb2HeaderRead(&hdr, &reader);
		cmBufferWriterInit(&writer , nsSkipHeader(context->socket, staticData->responseBuffer) , 64);
		cmSmb2HeaderWrite(&hdr , &writer);

		if (pSession->dialect < CS_DIALECT_SMB30)
		{
			csCreateMessageSignatureSMB2(context->prot.smb2.sid.low, nsSkipHeader(context->socket, staticData->responseBuffer), packetLen);
		}
#ifdef UD_NQ_INCLUDESMB3
		else if (pSession->dialect >= CS_DIALECT_SMB30)
		{
			csCreateMessageSignatureSMB3(context->prot.smb2.sid.low, nsSkipHeader(context->socket, staticData->responseBuffer), packetLen);
		}
#endif /* UD_NQ_INCLUDESMB3 */
    }
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

#ifdef UD_NQ_INCLUDESMBCAPTURE
    sockDescr = csGetClientSocketDescriptorBySocket(context->socket);
    if (sockDescr != NULL)
    {
		sockDescr->captureHdr.receiving = FALSE;
		cmCapturePacketWriteStart(&sockDescr->captureHdr , packetLen);
		cmCapturePacketWritePacket(staticData->responseBuffer + 4, packetLen);
		cmCapturePacketWriteEnd();
    }
#endif /* UD_NQ_INCLUDESMBCAPTURE */
#ifdef UD_NQ_INCLUDESMB3
    if (isEncrypted)  			/* !!!! TODO: if packet is encrypted*/
	{
    	NQ_INT	nbHeader;

    	nbHeader = nsSkipHeader(staticData->savedSocket, staticData->responseBuffer) == (NQ_BYTE *)staticData->responseBuffer ? 0 : 4;
    	syMemcpy(&encryptBuf[SMB2_TRANSFORMHEADER_SIZE + nbHeader], &staticData->responseBuffer[nbHeader] , packetLen);
		cs2TransformHeaderEncrypt( NULL , &encryptBuf[nbHeader] , packetLen);
		packetLen = packetLen + SMB2_TRANSFORMHEADER_SIZE;
	}
#endif /* UD_NQ_INCLUDESMB3 */
    packetLen = nsPrepareNBBuffer(
#ifdef UD_NQ_INCLUDESMB3
    		isEncrypted ? encryptBuf :
#endif
    				staticData->responseBuffer, packetLen, packetLen);
    if(0 == packetLen)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error prepare buffer for late response");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
    }

    if (packetLen != (NQ_COUNT)nsSendFromBuffer(
                context->socket, 
#ifdef UD_NQ_INCLUDESMB3
                isEncrypted ? encryptBuf :
#endif
                		staticData->responseBuffer,
                packetLen,
                packetLen,
                NULL
                )
          )
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending late response");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return TRUE;
}

/*====================================================================
 * PURPOSE: Send an interim response
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the incoming request header
 *          
 * RETURNS: Generated Async ID
 *
 * NOTES:   
 *====================================================================
 */

NQ_UINT32 csSmb2SendInterimResponse(
    CMSmb2Header * in              
    )
{
    CMSmb2Header out;           /* outgoing header */
    CMBufferWriter writer;      /* response writer */
    NQ_BYTE outBuffer[SMB2_HEADERSIZE + 10 + 8];    /* response buffer */ 
    NQ_BYTE encryptedBuffer[SMB2_TRANSFORMHEADER_SIZE + SMB2_HEADERSIZE + 10 + 8];    /* encrypted response buffer */
    NQ_COUNT expected;          /* expected packet length to send */
    NQ_INT sent = 0;            /* actually sent bytes */
    CSSession *pSession = NULL;
    CSUser *pUser = NULL;
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor *	sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    NQ_BOOL	isEncrypted = staticData->encrypedPacket;
    
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    pUser = csGetUserByUid((CSUid)sessionIdToUid(in->sid.low));
    if (NULL == pUser)
    {
         LOGERR(CM_TRC_LEVEL_ERROR, "Sending interim response failed, invalid session");
         LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
         return 0;
    }
    pSession = csGetSessionById(pUser->session);
    if (NULL == pSession)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Sending interim response failed, invalid session");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return 0;
    }

    out = *in;      /* copy fields */
    cmBufferWriterInit(&writer, nsSkipHeader(staticData->savedSocket, outBuffer), sizeof(outBuffer));
    cmSmb2HeaderSetForResponse(&out, &writer, (NQ_UINT16)pSession->creditsToGrant);
    out.flags |= SMB2_FLAG_ASYNC_COMMAND;
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    if (pSession->signingOn)
        out.flags |= SMB2_FLAG_SIGNED;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
    out.status = SMB_STATUS_PENDING;
    cs2GenerateNextAsyncId(&out.aid);
    cmSmb2HeaderWrite(&out, &writer);
    writeErrorResponseData(&writer);
    expected = cmBufferWriterGetDataCount(&writer);
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    if (pSession->dialect < CS_DIALECT_SMB30)
	{
		csCreateMessageSignatureSMB2(out.sid.low, nsSkipHeader(staticData->savedSocket, outBuffer), expected);
	}
#ifdef UD_NQ_INCLUDESMB3
	else if (pSession->dialect >= CS_DIALECT_SMB30 && !isEncrypted)
	{
		csCreateMessageSignatureSMB3(out.sid.low, nsSkipHeader(staticData->savedSocket, outBuffer), expected);
	}
#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
    
#ifdef UD_NQ_INCLUDESMBCAPTURE
    sockDescr = csGetClientSocketDescriptorBySocket(staticData->savedSocket);
    if (sockDescr != NULL)
    {
		sockDescr->captureHdr.receiving = FALSE;
		cmCapturePacketWriteStart(&sockDescr->captureHdr, expected);
		cmCapturePacketWritePacket(outBuffer + 4, expected);
		cmCapturePacketWriteEnd();
    }
#endif /* UD_NQ_INCLUDESMBCAPTURE */
#ifdef UD_NQ_INCLUDESMB3
    if (isEncrypted)
	{
    	NQ_INT	nbHeader;
    	NQ_INT	skip = SMB2_TRANSFORMHEADER_SIZE;

    	syMemset(&encryptedBuffer , 0 , sizeof(encryptedBuffer));
    	nbHeader = (nsSkipHeader(staticData->savedSocket, outBuffer) == (NQ_BYTE *)outBuffer) ? 0 : 4;
    	skip += nbHeader;

    	syMemcpy((NQ_BYTE *)&encryptedBuffer[skip], (NQ_BYTE *)&outBuffer[nbHeader] , expected);
		cs2TransformHeaderEncrypt(NULL, (NQ_BYTE *)&encryptedBuffer[nbHeader], expected);
		expected = expected + SMB2_TRANSFORMHEADER_SIZE;
	}
#endif /* UD_NQ_INCLUDESMB3 */
    expected = nsPrepareNBBuffer(isEncrypted ? encryptedBuffer : outBuffer, expected, expected);
	if (0 == expected)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, "prepare buffer for interim response failed");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return 0;
	}

    sent = nsSendFromBuffer(
                            staticData->savedSocket,
                            isEncrypted ? encryptedBuffer : outBuffer,
                            expected,
                            expected,
                            NULL
                            );

    if (sent != expected)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Sending interim response failed: size=%d, sent=%d", expected, sent);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return 0;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return out.aid.low;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */
