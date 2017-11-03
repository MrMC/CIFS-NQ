/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 tree connect/disconnect command handler
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 05-Jan-2009
 ********************************************************************/

#include "cmsmb2.h"
#include "csdataba.h"
#include "csutils.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

#define SMB2_TREE_CONNECT_RESPONSE_DATASIZE             16
#define SMB2_TREE_DISCONNECT_RESPONSE_DATASIZE          4

/* SMB2 share types */
#define SMB2_SHARE_TYPE_DISK                            0x01        /* Disk share */
#define SMB2_SHARE_TYPE_PIPE                            0x02        /* Named pipe share */
#define SMB2_SHARE_TYPE_PRINT                           0x03        /* Printer share */

/* SMB2 share flags */
#define SMB2_SHARE_FLAG_MANUAL_CACHING                  0x00000000  /* The client MAY cache files that are explicitly selected by the user for offline use. */
#define SMB2_SHARE_FLAG_AUTO_CACHING                    0x00000010  /* The client MAY automatically cache files that are used by the user for offline access. */
#define SMB2_SHARE_FLAG_VDO_CACHING                     0x00000020  /* The client MAY automatically cache files that are used by the user for offline access, and MAY use those files in an offline mode */
#define SMB2_SHARE_FLAG_NO_CACHING                      0x00000030  /* Offline caching MUST NOT occur. */
#define SMB2_SHARE_FLAG_DFS                             0x00000001  /* The specified share is present in a DFS tree structure. */
#define SMB2_SHARE_FLAG_DFS_ROOT                        0x00000002  /* The specified share is the root volume in a DFS tree structure. */
#define SMB2_SHARE_FLAG_RESTRICT_EXCLUSIVE_OPENS        0x00000100  /* The specified share disallows exclusive file opens that deny reads to an open file. */
#define SMB2_SHARE_FLAG_FORCE_SHARED_DELETE             0x00000200  /* Shared files in the specified share can be forcibly deleted. */
#define SMB2_SHARE_FLAG_ALLOW_NAMESPACE_CACHING         0x00000400  /* Clients are allowed to cache the namespace of the specified share. */
#define SMB2_SHARE_FLAG_ACCESS_BASED_DIRECTORY_ENUM     0x00000800  /* The server will filter directory entries based on the access permissions of the client. */

#define SMB2_SHARE_FLAG_ENCRYPT_DATA					0x00008000

/* todo: temporary */
#define SMB2_DEFAULT_SHARE_ACCESS_MASK                  0x001f01ff


/*====================================================================
 * PURPOSE: Perform Tree Connect processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Tree Connect command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnTreeConnect(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *pSession, CSUser *pUser, CSTree *tree, CMBufferWriter *writer)
{
    CSShare* pShare;                      /* pointer to share */
    NQ_UINT16 pathOffset;                 /* offset to path in request */  
    NQ_UINT16 pathLength;                 /* path length in request */
    NQ_STATIC NQ_WCHAR tcharPath[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];  /* buffer for full share path */
    NQ_WCHAR *pShareName;                 /* pointer share component of the path */
    NQ_UINT32 shareFlags = 0;
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDShareAccessEvent eventInfo;               /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* parse the request */
    cmBufferReaderSkip(reader, 2);   /* reserved */
    cmBufferReadUint16(reader, &pathOffset);
    cmBufferReadUint16(reader, &pathLength);
    
    /* find share component in the requested path */
    syWStrncpy(tcharPath, (NQ_WCHAR*)reader->current, (NQ_UINT)(pathLength / sizeof(NQ_WCHAR)));
    *(tcharPath + pathLength / sizeof(NQ_WCHAR)) = cmWChar('\0');
    pShareName = syWStrrchr(tcharPath, cmWChar('\\'));
    if (pShareName == NULL)
        pShareName = tcharPath;
    ++pShareName;    
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "requested share: %s", cmWDump(pShareName));

    /* find share descriptor for the requested share */
    pShare = csGetShareByName(pShareName);
    if (pShare == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "share not found");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_BAD_NETWORK_NAME;
    }
    TRC("share mapped to %s %s", cmWDump(pShare->map), pShare->ipcFlag ? "(IPC)" : "");

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.shareName = pShareName;
    eventInfo.ipc = pShare->ipcFlag;
    eventInfo.printQueue = pShare->isPrintQueue;
    eventInfo.tid = CS_ILLEGALID;
#endif

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    /* reload security descriptor for the share */
    if (!pShare->isHidden)
        csLoadShareSecurityDescriptor(pShare);
#endif

    /* allow access to hidden ($) share for admins only */
    if (pShare->isHidden && (pUser->isAnonymous ||
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS   
            !cmSdHasAccess(&pUser->token, pShare->sd.data, SMB_DESIREDACCESS_READDATA)))
#else
            FALSE))
#endif        
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "User without administrative rights attempts to connect to hidden administrative share");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_ACCESS_VIOLATION;
    }

    /* allow anonymous user to connect only to IPC$ */
   /* if (session->isAnonymous && !pShare->ipcFlag && !pShare->isPrintQueue)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "anonymous user attempts to connect to non-IPC$ share");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_ACCESS_DENIED;
    }*/

    /* check the existence of the underlying path */
    if (!csCheckShareMapping(pShare))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "share is mapped on an invalid path");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_BAD_NETWORK_NAME;
    }
#if defined(UD_NQ_INCLUDESMB3) && !defined(UD_CS_ALLOW_NONENCRYPTED_ACCESS_TO_ENCRYPTED_SHARE)
    if (pShare->isEncrypted && (pSession->dialect < CS_DIALECT_SMB30))
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "share requires encrypted access and the current connection can't encrypt");
		LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
		return SMB_STATUS_ACCESS_DENIED;
	}
#endif /* defined(UD_NQ_INCLUDESMB3) && !defined(UD_CS_ALLOW_NONENCRYPTED_ACCESS_TO_ENCRYPTED_SHARE) */

    /* find a free entry in the tree table */
    tree = csGetNewTree(pUser);
    if (tree == NULL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog (
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            (NQ_UINT32)SMB_STATUS_INSUFFICIENT_RESOURCES,
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        LOGERR(CM_TRC_LEVEL_ERROR, "tree table overflow");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_UNSUCCESSFUL;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "tid: %d", tree->tid);
    
    /* fill tree information */
    tree->share = pShare;
    if (!pShare->ipcFlag)
    {
        udServerShareConnect(pShare->name);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.tid = tree->tid;
    udEventLog (
        UD_LOG_MODULE_CS,
        UD_LOG_CLASS_SHARE,
        UD_LOG_SHARE_CONNECT,
        pUser->name,
        pUser->ip,
        0,
        (const NQ_BYTE*)&eventInfo
        );
#endif
    shareFlags = pShare->ipcFlag || pShare->isPrintQueue ? SMB2_SHARE_FLAG_NO_CACHING : SMB2_SHARE_FLAG_MANUAL_CACHING;
#ifdef UD_NQ_INCLUDESMB3
    if (pShare->isEncrypted)
    {
    	shareFlags |= ((pSession->dialect >= CS_DIALECT_SMB30) && !pShare->ipcFlag) ? SMB2_SHARE_FLAG_ENCRYPT_DATA : 0;
    }
#endif /* UD_NQ_INCLUDESMB3 */
    /* write the response */
    out->tid = tree->tid;                                              /* set tid in the response header */
    cmBufferWriteUint16(writer, SMB2_TREE_CONNECT_RESPONSE_DATASIZE);  /* constant response size */
    cmBufferWriteByte(writer, pShare->ipcFlag ? SMB2_SHARE_TYPE_PIPE : (pShare->isPrintQueue ? SMB2_SHARE_TYPE_PRINT : SMB2_SHARE_TYPE_DISK)); /* share type */    
    cmBufferWriteByte(writer, 0);                                      /* reserved (0)  */
    cmBufferWriteUint32(writer, shareFlags); /* share flags */
    cmBufferWriteUint32(writer, 0);                                    /* share capabilities (not DFS) */
    cmBufferWriteUint32(writer, SMB2_DEFAULT_SHARE_ACCESS_MASK);       /* share access mask */  

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}


/* actual tree disconnect function defined in cstreeco.c */
void csDoTreeDisconnect(CSTree *tree);


/*====================================================================
 * PURPOSE: Perform Tree Disconnect processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Tree Disconnect command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnTreeDisconnect(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "tid: %d", tree->tid);

    /* disconnect the tree */
    csDoTreeDisconnect(tree);

    /* write the response */
    cmBufferWriteUint16(writer, SMB2_TREE_DISCONNECT_RESPONSE_DATASIZE);  /* constant response size */
    cmBufferWriteUint16(writer, 0);                                       /* reserved (0) */

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */


