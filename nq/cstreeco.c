/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Tree Connect/Disconnect
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 29-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "csutils.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements tree-related commands.
 */

/*====================================================================
 * PURPOSE: Perform TREE_CONNECT command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComTreeConnect(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsTreeConnectRequest* connectRequest;   /* casted request */
    CMCifsTreeConnectResponse* connectResponse; /* casted response */
    CSUser* pUser;                              /* pointer to the user descriptor */
    NQ_UINT32 returnValue;                      /* error code returnes by other routines - NT */
    NQ_BOOL unicodeRequired;                    /* client requires UNICODE */
    NQ_BYTE* path;                              /* pointer to the path string in the request */
    NQ_BYTE* password;                          /* pointer to the password string in the request */
    NQ_BYTE* service;                           /* pointer to the service string in the request */
    NQ_STATIC NQ_TCHAR tcharPath[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_FILENAMELEN)];  /* full path to the share in ascii */
    NQ_TCHAR *pShareName;                       /* required share */
    CSShare* pShare;                            /* share descriptor from the server share list */
    CSTree* pTree;                              /* pointer to a new tree slot */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDShareAccessEvent eventInfo;               /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check space in output buffer and set up flags in response */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*connectResponse)))
         != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* search the session table for the user UID */

    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    if (!pUser)
    {
        TRCERR("unknown UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

    /* check Word Count and Byte Count */

    connectRequest = (CMCifsTreeConnectRequest*)pRequest;

    if (   connectRequest->wordCount != 0
        || cmLtoh16(cmGetSUint16(connectRequest->byteCount)) < SMB_TREECONNECT_REQUEST_MINBYTES
       )
    {
        TRCERR("Unexpected word, byte count or buffer format");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* set the pointers to path, password and service */

    if (connectRequest->bufferFormat != SMB_FIELD_ASCII)
    {
        TRCERR("Unexpected buffer format for path");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    path = (NQ_BYTE*)(connectRequest + 1);
    if (unicodeRequired)
    {
        path = cmAllignTwo(path);
        password = path + (cmWStrlen((NQ_WCHAR*)path) + 1) * sizeof(NQ_WCHAR);
        password = cmAllignTwo(password);
    }
    else
    {
        password = (NQ_BYTE*)(path + syStrlen((NQ_CHAR*)path) + 1);
    }
    if (*password++ != SMB_FIELD_ASCII)
    {
        TRCERR("Unexpected buffer format for password");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    if (unicodeRequired)
    {
        service = password + (cmWStrlen((NQ_WCHAR*)password) + 1) * sizeof(NQ_WCHAR);
        service = cmAllignTwo(service);
    }
    else
    {
        service = (password + syStrlen((NQ_CHAR*)password) + 1);
    }
    if (*service++ != SMB_FIELD_ASCII)
    {
        TRCERR("Unexpected buffer format for service");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find the share name */

    if (unicodeRequired)
    {
        path = cmAllignTwo(path);
        cmUnicodeToTchar(tcharPath, (NQ_WCHAR*)path);
    }
    else
    {
        cmAnsiToTchar(tcharPath, (NQ_CHAR*)path);
    }

    pShareName = cmTStrrchr(tcharPath, cmTChar('\\'));
    if (pShareName == NULL)
    {
        pShareName = tcharPath;
    }
    else
    {
        *pShareName++ = '\0';
    }

    /* find descriptor for the required share */

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.shareName = pShareName;
    eventInfo.ipc = FALSE;
    eventInfo.printQueue = FALSE;
    eventInfo.rid = CS_ILLEGALID;
    eventInfo.tid = CS_ILLEGALID;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    pShare = csGetShareByName(pShareName);
    if (pShare == NULL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Share not found");
        TRC1P("  required share: %s", cmTDump(pShareName));
        TRCE();
        return csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare);
    }
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    /* reload security descriptor for share */
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
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog (
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("User without administrative rights attempts to connect to hidden administrative share");
        TRCE();
        return csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
    }

    /* allow anonymous user to connect only to IPC$ */

    if (pUser->isAnonymous && !pShare->ipcFlag)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Anonymous user attempts to connect to non-IPC$ share");
        TRCE();
        return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
    }

    /* check the existence of the underlying path */
    if (!csCheckShareMapping(pShare))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Share is mapped on an invalid path");
        TRCE();
        return csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare);
    }

    /* check the service name */
    if (syStrcmp((NQ_CHAR*)service, "A:") == 0)
    {
        if (pShare->ipcFlag)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_SHARE,
                UD_LOG_SHARE_CONNECT,
                pUser->name,
                pUser->ip,
                csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc),
                (const NQ_BYTE*)&eventInfo
            );
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Service is A: while share name is IPC$");
            TRCE();
            return csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc);
        }
    }
    else if (syStrcmp((NQ_CHAR*)service, "IPC") == 0)
    {
        if (!pShare->ipcFlag)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog (
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_SHARE,
                UD_LOG_SHARE_CONNECT,
                pUser->name,
                pUser->ip,
                csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc),
                (const NQ_BYTE*)&eventInfo
            );
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Service is IPC but share name is not IPC$");
            TRCE();
            return csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc);
        }
    }
    else if (syStrcmp((NQ_CHAR*)service, "?????") == 0)
    {
    }
    else
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unsupported service");
        TRC1P("  service: %s", service);
        TRCE();
        return csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc);
    }

    /* find a free entry in the tree table */

    pTree = csGetNewTree(pUser);
    if (pTree == NULL)
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
        TRCERR("Tree table overflow");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* fill tree information */

    pTree->share = pShare;

    if (!pShare->ipcFlag)
    {
        udServerShareConnect(pShare->name);
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.tid = pTree->tid;
    udEventLog (
        UD_LOG_MODULE_CS,
        UD_LOG_CLASS_SHARE,
        UD_LOG_SHARE_CONNECT,
        pUser->name,
        pUser->ip,
        0,
        (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* prepare the response */

    cmPutSUint16(pHeaderOut->tid, cmHtol16(pTree->tid));

    connectResponse = (CMCifsTreeConnectResponse*)*pResponse;

    connectResponse->wordCount = SMB_TREECONNECT_RESPONSE_WORDCOUNT;
    cmPutSUint16(connectResponse->maxBufferSize, cmHtol16(CIFS_MAX_DATA_SIZE16));
    cmPutSUint16(connectResponse->tid, cmHtol16(pTree->tid));
    cmPutSUint16(connectResponse->byteCount, 0);

    *pResponse += sizeof(*connectResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform TREE_CONNECT_ANDX command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComTreeConnectAndX(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsTreeConnectAndXRequest* connectRequest;   /* casted request */
    CMCifsTreeConnectAndXResponse* connectResponse; /* casted response */
    CSUser* pUser;                                  /* pointer to the user descriptor */
    NQ_UINT32 returnValue;                             /* error code returnes by other routines - NT */
    NQ_BOOL unicodeRequired;                           /* client requires UNICODE */
    NQ_BYTE* path;                                     /* pointer to the path string in the request */
    NQ_BYTE* password;                                 /* pointer to the password string in the request */
    NQ_BYTE* service;                                  /* pointer to the service string in the request */
    NQ_STATIC NQ_TCHAR tcharPath[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_FILENAMELEN)];  /* full path to the share in ascii */
    NQ_TCHAR *pShareName;                           /* required share */
    CSShare* pShare;                                /* share descriptor from the server share list */
    CSTree* pTree;                                  /* pointer to a new tree slot */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDShareAccessEvent eventInfo;                   /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*connectResponse) + sizeof("IPC") + 1)
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* search the session table for the user UID */

    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    if (!pUser)
    {
        TRCERR("Unknown UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = CS_ILLEGALID;
#endif

    /* check Word Count and Byte Count */

    connectRequest = (CMCifsTreeConnectAndXRequest*)pRequest;

    if (   connectRequest->wordCount != SMB_TREECONNECTANDX_REQUEST_WORDCOUNT
        || cmLtoh16(cmGetSUint16(connectRequest->byteCount)) < SMB_TREECONNECTANDX_REQUEST_MINBYTES
       )
    {
        TRCERR("Unexpected word or byte count");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* check the next command to be an allowed one */

    switch (connectRequest->andXCommand)
    {
    case SMB_COM_OPEN:
    case SMB_COM_CREATE:
    case SMB_COM_CREATE_DIRECTORY:
    case SMB_COM_COPY:
    case SMB_COM_DELETE_DIRECTORY:
    case SMB_COM_FIND_UNIQUE:
    case SMB_COM_GET_PRINT_QUEUE:
    case SMB_COM_RENAME:
    case SMB_COM_SET_INFORMATION:
    case SMB_COM_CREATE_NEW:
    case SMB_COM_TRANSACTION:
    case SMB_COM_CHECK_DIRECTORY:
    case SMB_COM_QUERY_INFORMATION:
    case SMB_COM_OPEN_ANDX:
    case SMB_COM_DELETE:
    case SMB_COM_FIND:
    case 0xFF:
        break;
    default:
        TRCERR("Illegal command follows Tree Connect AndX");
        TRC1P("  command: %d", (NQ_INT)connectRequest->andXCommand);
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* set the pointers to path, password and service */

    password = (NQ_BYTE*)(connectRequest + 1);
    path = password + cmLtoh16(cmGetSUint16(connectRequest->passwordLength));
    if (unicodeRequired)
    {
        path = cmAllignTwo(path);
        service = path + (cmWStrlen((NQ_WCHAR*)path) + 1) * sizeof(NQ_WCHAR);
    }
    else
    {
        service = path + syStrlen((NQ_CHAR*)path) + 1;
    }

    /* find the share name */

    if (unicodeRequired)
    {
        path = cmAllignTwo(path);
        cmUnicodeToTchar(tcharPath, (NQ_WCHAR*)path);
    }
    else
    {
        cmAnsiToTchar(tcharPath, (NQ_CHAR*)path);
    }

    pShareName = cmTStrrchr(tcharPath, cmTChar('\\'));
    if (pShareName == NULL)
    {
        pShareName = tcharPath;
    }
    else
    {
        *pShareName++ = '\0';
    }

    /* find descriptor for the required share */

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.shareName = pShareName;
    eventInfo.ipc = FALSE;
    eventInfo.printQueue = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    pShare = csGetShareByName(pShareName);
    if (pShare == NULL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog (
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Share not found");
        TRC1P("  required share: %s", cmTDump(pShareName));
        TRCE();
        return csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare);
    }

    TRC1P("share found with name: %s", cmTDump(pShare->name));
    TRC1P(" path %s", cmTDump(pShare->map));
#ifdef UD_NQ_INCLUDEEVENTLOG
    pTree = csGetNextTreeByShare(pShare , CS_ILLEGALID);
    eventInfo.tid = pTree ? pTree->tid : -1;
#endif

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    /* reload security descriptor for share */
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
#ifdef UD_NQ_INCLUDEEVENTLOG

        udEventLog (
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("User without administrative rights attempts to connect to hidden administrative share");
        TRCE();
        return csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
    }
    
    /* allow anonymous user to connect only to IPC$ and printer share */

/*    if (pUser->isAnonymous && !pShare->ipcFlag && !pShare->isPrintQueue)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog (
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess),
            (const NQ_BYTE*)&eventInfo
        );
#endif*/ /* UD_NQ_INCLUDEEVENTLOG */
/*        TRCERR("Anonymous user attempts to connect to non-IPC$ share");
        TRCE();
        return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
    }*/

    /* check the existence of the underlying path */
    if (!csCheckShareMapping(pShare))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Share is mapped on an invalid path");
        TRCE();
        return csErrorReturn(SMB_STATUS_BAD_NETWORK_NAME, DOS_ERRnoshare);
    }

    /* prepare the response */

    connectResponse = (CMCifsTreeConnectAndXResponse*)*pResponse;

    connectResponse->wordCount = SMB_TREECONNECTANDX_RESPONSE_WORDCOUNT;
    connectResponse->andXCommand = connectRequest->andXCommand;
    connectResponse->andXReserved = 0;

    /* disconnect TID if required */

    if (cmLtoh16(cmGetSUint16(connectRequest->flags)) & 0x1)
    {
        if ((pTree = csGetTreeByTid(cmLtoh16(cmGetSUint16(pHeaderOut->tid)))) != NULL)
        {
            csReleaseTree(pTree->tid , TRUE);
        }
    }

    /* check the service name */

    if (syStrcmp((NQ_CHAR*)service, "A:") == 0)
    {
        if (pShare->ipcFlag)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog (
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_SHARE,
                UD_LOG_SHARE_CONNECT,
                pUser->name,
                pUser->ip,
                csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc),
                (const NQ_BYTE*)&eventInfo
            );
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Servic is A: while share name is IPC$");
            TRCE();
            return csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc);
        }
    }
    else if (syStrcmp((NQ_CHAR*)service, "IPC") == 0)
    {
        if (!pShare->ipcFlag)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog (
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_SHARE,
                UD_LOG_SHARE_CONNECT,
                pUser->name,
                pUser->ip,
                csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc),
                (const NQ_BYTE*)&eventInfo
            );
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Service is IPC but share name is not IPC$");
            TRCE();
            return csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc);
        }
    }
    else if (syStrcmp((NQ_CHAR*)service, "?????") == 0)
    {
    }
    else
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog (
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_SHARE,
            UD_LOG_SHARE_CONNECT,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unsupported service");
        TRC1P("  service: %s", service);
        TRCE();
        return csErrorReturn(SMB_STATUS_BAD_DEVICE_TYPE, DOS_ERRdontsupportipc);
    }

    /* We do not have optional support */

    cmPutSUint16(connectResponse->optionalSupport, 0);

    /* Copy service into the response. For ????? service treat share name IPC$ as
       IPC service, any other name as A: service.
       Copy fielsystem name into the response. */

    {
        NQ_CHAR* pStr;                                              /* pointer to strings in the response */
        NQ_STATIC NQ_TCHAR fsName[CM_BUFFERLENGTH(NQ_TCHAR, 100)];  /* buffer for converting FS name into Unicode */

        pStr = (NQ_CHAR*)(connectResponse + 1);

        if (syStrcmp((NQ_CHAR*)service, "?????") == 0)
        {
            if (pShare->ipcFlag)
            {
                syStrcpy(pStr, "IPC");
            }
            else if (pShare->isPrintQueue)
            {
                syStrcpy(pStr, "LPT1:");
            }
            else
            {
                syStrcpy(pStr, "A:");
            }
        }
        else
        {
            syStrcpy(pStr, (NQ_CHAR*)service);
        }

        pStr += syStrlen(pStr) + 1;

        if (pShare->ipcFlag)
            cmAnsiToTchar(fsName, "IPC");
        else
        {
            udGetFileSystemName(pShare->name, pShare->map,  fsName);
        }
        if (unicodeRequired)
        {
            pStr = (NQ_CHAR*)cmAllignTwo(pStr);
            cmTcharToUnicode((NQ_WCHAR*)pStr, fsName);
            pStr += (cmWStrlen((const NQ_WCHAR*)pStr) + 1) * sizeof(NQ_WCHAR);
        }
        else
        {
            cmTcharToAnsi(pStr, fsName);
            pStr += syStrlen(pStr) + 1;
        }

        cmPutSUint16(connectResponse->byteCount, cmHtol16((NQ_UINT16)((NQ_BYTE*)pStr - (NQ_BYTE*)(connectResponse + 1))));
    }


    /* find a free entry in the tree table */

    pTree = csGetNewTree(pUser);
    if (pTree == NULL)
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
        TRCERR("Tree table overflow");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }
    pTree->share = pShare;

    if (!pShare->ipcFlag)
    {
        udServerShareConnect(pShare->name);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.tid = pTree->tid;
    eventInfo.ipc = pShare->ipcFlag;
    eventInfo.printQueue = pShare->isPrintQueue;
    udEventLog(
        UD_LOG_MODULE_CS,
        UD_LOG_CLASS_SHARE,
        UD_LOG_SHARE_CONNECT,
        pUser->name,
        pUser->ip,
        0,
        (const NQ_BYTE*)&eventInfo
    );
#endif /* UD_NQ_INCLUDEEVENTLOG */

    cmPutSUint16(pHeaderOut->tid, cmHtol16(pTree->tid));

    /* setup the next command offset */

    {
        NQ_UINT offset;            /* for calculating offsets */

        offset =   (NQ_UINT)(sizeof(*connectResponse)
                 + cmLtoh16(cmGetSUint16(connectResponse->byteCount)));
        *pResponse += offset;

        offset =   (NQ_UINT)((NQ_BYTE*)connectResponse + offset - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(connectResponse->andXOffset, cmHtol16((NQ_UINT16)offset));
    }

    TRCE();
    return 0;
}

/**
 * <b>Disconnect existing tree</b>
 * Also called from cs2trcn.c (SMB2_TREE_DISCONNECT)
 */
void csDoTreeDisconnect(CSTree *tree)
{
    if (!tree->share->ipcFlag)
    {
        udServerShareDisconnect(tree->share->name);
    }

    csReleaseTree(tree->tid , TRUE);
}

/*====================================================================
 * PURPOSE: Perform TREE_DISCONNECT command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComTreeDisconnect(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsTreeDisconnect* disconnectRequest;    /* casted request */
    CMCifsTreeDisconnect* disconnectResponse;   /* casted response */
    NQ_UINT32 returnValue;                      /* error code returnes by other routines - NT */
    CSTree* pTree;                              /* pointer to a tree descriptor */
    CSTid tid;                                  /* requested TID */

    TRCB();

    if (   (returnValue =
            csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*disconnectResponse))) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    disconnectRequest = (CMCifsTreeDisconnect*)pRequest;
    disconnectResponse = (CMCifsTreeDisconnect*)*pResponse;

    /* check the request format */

    if (   disconnectRequest->wordCount != 0
        || cmGetSUint16(disconnectRequest->byteCount) != 0
       )
    {
        TRCERR("Unexpected word or byte count");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* disconnect TID */

    tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    if ((pTree = csGetTreeByTid(tid)) == NULL)
    {
        TRCERR("Unknown TID");
        TRC1P(" tid: %d", tid);
        disconnectResponse->wordCount = 0;
        cmPutSUint16(disconnectResponse->byteCount, 0);
        *pResponse += sizeof(*disconnectResponse);

        TRCE();
        return 0;
    }

    /* disconnect tree */
    csDoTreeDisconnect(pTree);

    disconnectResponse->wordCount = 0;
    cmPutSUint16(disconnectResponse->byteCount, 0);

    *pResponse += sizeof(*disconnectResponse);

    TRCE();
    return 0;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */


