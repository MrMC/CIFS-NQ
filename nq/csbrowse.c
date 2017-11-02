
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Server Announcement processing
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 17-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsapi.h"

#include "csbrowse.h"
#include "cstransa.h"
#include "csutils.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_USETRANSPORTNETBIOS)

/* This code implements HOST ANNOUNCEMENT for two cases:
    - as a response to a client's request sent as a BROWSE MAILSLOT command over the
      TRANSACTION subprotocols
    - as a periodic initiative message over the same protocol
    Message data is reused for the both cases
*/

/*
    Static data & functions
    -----------------------
 */

typedef struct
{
    NQ_TIME nextAnnouncementInterval;   /* next interval between announcements, this value
					                                        will raise up to CM_FS_MINHOSTANNOUNCEMENTINTERVAL */
    NSSocketHandle ddSocket;            /* socket for connecting to DD */
    CMNetBiosNameInfo dcName;           /* NetBIOS name (domain controller) to send announcment to */
    CMCifsServerAnnouncementRequest frame;    /* frame to send */
    NQ_BOOL frameReady;                 /* whether the frame is already filled with data */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* This frame is used for preparing HOST ANNOUNCEMENT. All but the timeout is filled only once
   When this frame is used for self-announcement - it is send as is
   When it is used as response to HOST ANNOUNCEMENT REQUEST, its data is copied into the
   response frame */

static const NQ_BYTE sCifsServerAnnouncementRequest[] =
{
    /* CIFS header */
    0xFF, 'S', 'M', 'B',
    SMB_COM_TRANSACTION,
    0x00, 0x00, 0x00, 0x00, /* Error */
    0x00,                   /* Flags */
    0x00, 0x00,             /* Flags 2 */
    0x00, 0x00,             /* Process ID high */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Signature */
    0x00, 0x00,             /* reserved (2) */
    0x00, 0x00,             /* Tree ID */
    0x00, 0x00,             /* Process ID */
    0x00, 0x00,             /* User ID */
    0x00, 0x00,             /* Multiplex ID */

    /* TRANSACTION header */
    0x11,                   /* Word count */
    0x00, 0x00,             /* Total parameter count */
    0x00, 0x00,             /* Total data count */
    0x00, 0x00,             /* Max parameter count */
    0x00, 0x00,             /* Max data count */
    0x00,                   /* Max setup count */
    0x00,                   /* Reserved */
    0x00, 0x00,             /* Flags */
    0x00, 0x00, 0x00, 0x00, /* Timeout */
    0x00, 0x00,             /* Reserved */
    0x00, 0x00,             /* Parameter count */
    0x00, 0x00,             /* Parameter offset */
    0x00, 0x00,             /* Data count */
    0x00, 0x00,             /* Data offset */
    0x03,                   /* Setup count */
    0x00,                   /* Reserved */

    /* setups */
    0x01, 0x00,     /* Write mail slot opcode */
    0x00, 0x00,     /* Priority */
    0x02, 0x00,     /* Class */

    0x00, 0x00,     /* Byte Count */

    /* browser name */
    '\\','M','A','I','L','S','L','O','T','\\','B','R','O','W','S','E', 0x00, /* SMB_SERVERANNOUNCEMENT_BROWSER, */

    /* announcement data (including server name placeholder) */
    0x01,                       /* Host Announcement command */
    0x00,                       /* Update count */
    0x00, 0x00, 0x00, 0x00,     /* Update periodicity */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Host name */
    CM_SOFTWAREVERSIONMAJOR,    /* OS major version */
    CM_SOFTWAREVERSIONMINOR,    /* OS minor version */
    0x00, 0x00, 0x00, 0x00,     /* Server type */
    0x00, 0x04,                 /* Browser protocol major and minor version */
    0x55, 0xAA,                 /* Server announcement signature */
    0x00
};

static void initializeFrame(void);    /* one-time initialization of the response frame */

/*
 *====================================================================
 * PURPOSE: initialize server announcement interval and the
 *          communication socket
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csInitBrowse(
    void
    )
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
       return NQ_FAIL;
#endif /* SY_FORCEALLOCATION */

    staticData->ddSocket = NULL;
    staticData->frameReady = FALSE;

    staticData->nextAnnouncementInterval = SMB_MIN_SERVER_ANNOUNCEMENT_INTERVAL;

    /* prepare communication socket */

    staticData->ddSocket = csPrepareSocket(NS_SOCKET_DATAGRAM, NS_TRANSPORT_NETBIOS);

    if (staticData->ddSocket == NULL)
    {
        TRCERR("Unable to create socket for communication with DD");

        return NQ_FAIL;
    }

    syMemcpy(&staticData->dcName, cmNetBiosGetDomain(), sizeof(CMNetBiosNameInfo));
    cmNetBiosNameFormat(staticData->dcName.name, CM_NB_POSTFIX_MASTERBROWSER);
    /* this is definitely NetBios group name! */
    staticData->dcName.isGroup = TRUE;

    return NQ_SUCCESS;
}

/*
 *====================================================================
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
csStopBrowse(
    void
    )
{
    if (staticData != NULL)
    {
        if (staticData->ddSocket != NULL)
        {
            nsClose(staticData->ddSocket);
            staticData->ddSocket = NULL;
        }

        staticData->frameReady = FALSE;
    }

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*
 *====================================================================
 * PURPOSE: perform Server Announcement for our server
 *--------------------------------------------------------------------
 * PARAMS:  Next announcement interval in seconds
 *
 * RETURNS: next announcement interval in seconds
 *
 * NOTES:   Broadcasts a Server Announcement messsage to the
 *          domain members. This routine uses a predefined frame filling
 *          only the next announcement interval value
 *====================================================================
 */

NQ_TIME
csAnnounceServer(
    void
    )
{
    NQ_TIME announcementInterval;     /* this announcement interval */

    TRCB();

    TRC3P("nextAnnouncementInterval: %ld sec, &ddSocket: %p, &frameReady: %p", staticData->nextAnnouncementInterval, &staticData->ddSocket, &staticData->frameReady);
    initializeFrame();

    /* next announcement interval */

    cmPutSUint32(staticData->frame.data.periodicity, cmHtol32(staticData->nextAnnouncementInterval * 1000));  /* in millisecs */

    /* ask DD to broadcast our announcement to the domain */

#ifdef UD_CS_INCLUDEHOSTANNOUNCEMENT
	if (*cmNetBiosGetHostNameZeroed() != '\0')
	{
	    if (nsSendToName(
	        staticData->ddSocket,
	        (const NQ_BYTE*)&staticData->frame,
	        sizeof(staticData->frame),
	        &staticData->dcName
	        ) != sizeof(staticData->frame))
	    {
	        TRCERR("Failed to send broadcast to DD");
	        TRCE();
	        return (NQ_TIME)NQ_FAIL;
	    }
	}
#endif

    /* calculate announcement interval */

    announcementInterval = staticData->nextAnnouncementInterval;
    staticData->nextAnnouncementInterval *= 2;
    if (staticData->nextAnnouncementInterval > SMB_MAX_SERVER_ANNOUNCEMENT_INTERVAL)
    {
        staticData->nextAnnouncementInterval = SMB_MAX_SERVER_ANNOUNCEMENT_INTERVAL;
    }

    TRCE();
    return announcementInterval;
}

/*====================================================================
 * PURPOSE: Continue processing TRANSACTION command for a MAILSLOT request
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to the TRANSACTION descriptor
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csMailslotBrowse(
    CSTransactionDescriptor* descriptor
    )
{
    NQ_UINT16 opcode;                               /* browse opcode */
    NQ_UINT16* pSetup;                              /* casted pointer to setup words + byteCount */
    CMCifsServerAnnouncementData* pAnnouncement;    /* pointer to announcement data */

    TRCB();

    /* find opcode */

    opcode = *(NQ_UINT16*)descriptor->dataIn;
    switch (opcode)
    {
    case 0x02:
        cmPutSUint16(descriptor->hdrOut->flags2, (NQ_UINT16)(cmGetSUint16(descriptor->hdrOut->flags2) & ~SMB_FLAGS2_UNICODE));   /* remove the (possible) UNICODE flag */
        initializeFrame();
        descriptor->paramCount = 0;
        descriptor->dataCount = sizeof(staticData->frame.data);
        descriptor->setupCount = SMB_SERVERANNOUNCEMENT_SETUPCOUNT;

        /* setups */

        pSetup = (NQ_UINT16*)descriptor->pBuf;
        *pSetup++ = cmHtol16(1);
        *pSetup++ = 0;
        *pSetup++ = 0;

        /* bytecount */

        *pSetup++ = cmHtol16(descriptor->dataCount);

        /* fill data - copy the appropriate portion of the predefined frame */

        pAnnouncement = (CMCifsServerAnnouncementData*)pSetup;
        descriptor->dataOut = (NQ_BYTE*)pSetup;
        syMemcpy(descriptor->dataOut, &staticData->frame.data, sizeof(staticData->frame.data));
        cmPutSUint32(pAnnouncement->periodicity, cmHtol32(staticData->nextAnnouncementInterval * 1000));  /* in millisecs */

        break;
    default:
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: initialize Server Announcement frame
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void initializeFrame()
{
    NQ_UINT16 count;

    if (staticData->frameReady)
        return;         /* already done */

    staticData->frameReady = TRUE;

    syMemcpy(&staticData->frame, sCifsServerAnnouncementRequest, sizeof(CMCifsServerAnnouncementRequest));

    /* write in constant values for the first time */

    syMemcpy(staticData->frame.data.serverName, cmNetBiosGetHostNameZeroed(), SMB_SERVER_NAMELEN);
    count = sizeof(staticData->frame.data);
    cmPutSUint16(staticData->frame.transHeader.totalDataCount, cmHtol16(count));
    cmPutSUint16(staticData->frame.transHeader.dataCount, cmHtol16(count));
    count = (NQ_UINT16)(count + sizeof(staticData->frame.name));
    cmPutSUint16(staticData->frame.byteCount, cmHtol16(count));
    count = (NQ_BYTE*)&staticData->frame.data - (NQ_BYTE*)&staticData->frame;
    cmPutSUint16(staticData->frame.transHeader.dataOffset, cmHtol16(count));

    /* swap UINT16 and UINT32 fields to little endian */
    cmPutSUint32(staticData->frame.data.installedServices, cmHtol32(csGetHostType()));
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

