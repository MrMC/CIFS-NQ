/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Create command handler
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Jan-2009
 ********************************************************************/

#include "csauth.h"
#include "cscreate.h"
#include "csutils.h"
#include "cs2disp.h"
#include "csbreak.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/* 
    Static functions, definitions and data 
    -------------------------------
 */

/* Context flags to compose context mask */
#define CONTEXT_SECD    0x01
#define CONTEXT_DHNQ    0x02
#define CONTEXT_DHNC    0x04
#define CONTEXT_ALSI    0x08
#define CONTEXT_MXAC    0x10

/* Table of context parsers */
static NQ_BOOL parseSecd(CMBufferReader * reader, NQ_UINT32 len, CSCreateContext * context);
static NQ_BOOL parseDhnq(CMBufferReader * reader, NQ_UINT32 len,  CSCreateContext * context);
static NQ_BOOL parseDhnc(CMBufferReader * reader,  NQ_UINT32 len, CSCreateContext * context);
static NQ_BOOL parseAlsi(CMBufferReader * reader,  NQ_UINT32 len, CSCreateContext * context);
static NQ_BOOL parseMxac(CMBufferReader * reader,  NQ_UINT32 len, CSCreateContext * context);
static NQ_UINT32 performSecd(CSCreateParams * params, const CSCreateContext * context);
static NQ_UINT32 performAlsi(CSCreateParams * params, const CSCreateContext * context);
#ifdef UD_CS_INCLUDEPERSISTENTFIDS 
/*static NQ_UINT32 performDhnq(CSCreateParams * params, const CSCreateContext * context);*/
static NQ_UINT32 performDhnc(CSCreateParams * params, const CSCreateContext * context);
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */
static NQ_UINT32 packMxac(CMBufferWriter * writer,  CSCreateParams * params, const CSCreateContext * context);
#ifdef UD_CS_INCLUDEPERSISTENTFIDS 
/*static NQ_UINT32 packDhnq(CMBufferWriter * writer,  CSCreateParams * params, const CSCreateContext * context);*/
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */
typedef struct 
{
    const NQ_CHAR * name;   /* expected context name */
    NQ_UINT32 flag;         /* this context flag */
    NQ_BOOL (*parser)(CMBufferReader *, NQ_UINT32, CSCreateContext *); /* pointer to the parser */
    NQ_UINT32 (*performer)(CSCreateParams *, const CSCreateContext *); /* pointer to the packer */
    NQ_UINT32 (*packer)(CMBufferWriter *, CSCreateParams *, const CSCreateContext *); /* pointer to the packer */
}
ContextParser;
ContextParser contextDescriptors[] = {
    { "MxAc", CONTEXT_MXAC, parseMxac, NULL, packMxac },
    { "SecD", CONTEXT_SECD, parseSecd, performSecd, NULL },
#ifdef UD_CS_INCLUDEPERSISTENTFIDS 
    { "DHnQ", CONTEXT_DHNQ, parseDhnq, NULL, NULL, /*performDhnq, packDhnq*/ },
    { "DHnC", CONTEXT_DHNC, parseDhnc, performDhnc, NULL },
#else /* UD_CS_INCLUDEPERSISTENTFIDS */
    { "DHnQ", CONTEXT_DHNQ, parseDhnq, NULL, NULL },
    { "DHnC", CONTEXT_DHNC, parseDhnc, NULL, NULL },
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */
    { "ALSi", CONTEXT_ALSI, parseAlsi, performAlsi, NULL },
};

/* Convert Posiz access mask into NT access mask */
/*static NQ_UINT32 posixAccesstoNtAccess(const CSFile * pFile);*/

/* NT Access mask */

#define MASK_FILE_READ_DATA 0x00000001 /* This value indicates the right to read data from the file or named pipe.*/
#define MASK_FILE_WRITE_DATA 0x00000002 /* This value indicates the right to write data into the file or named pipe beyond the end of the file.*/
#define MASK_FILE_APPEND_DATA 0x00000004 /* This value indicates the right to append data into the file or named pipe.*/
#define MASK_FILE_READ_EA 0x00000008 /* This value indicates the right to read the extended attributes of the file or named pipe.*/
#define MASK_FILE_WRITE_EA 0x00000010 /* This value indicates the right to write or change the extended attributes to the file or named pipe.*/
#define MASK_FILE_EXECUTE 0x00000020 /* This value indicates the right to execute the file.*/
#define MASK_FILE_READ_ATTRIBUTES 0x00000080 /* This value indicates the right to read the attributes of the file.*/
#define MASK_FILE_WRITE_ATTRIBUTES 0x00000100 /* This value indicates the right to change the attributes of the file.*/
#define MASK_DELETE 0x00010000 /* This value indicates the right to delete the file.*/
#define MASK_READ_CONTROL 0x00020000 /* This value indicates the right to read the security descriptor for the file or named pipe.*/
#define MASK_WRITE_DAC 0x00040000 /* This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure*/
#define MASK_WRITE_OWNER 0x00080000 /* This value indicates the right to change the owner in the security descriptor for the file or named pipe.*/
#define MASK_SYNCHRONIZE 0x00100000 /* This value SHOULD NOT be used by the sender and MUST be ignored by the receiver.*/
#define MASK_ACCESS_SYSTEM_SECURITY 0x01000000 /* This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure.*/
#define MASK_FILE_GENERIC_EXECUTE (MASK_FILE_READ_ATTRIBUTES| MASK_FILE_EXECUTE| MASK_SYNCHRONIZE| MASK_READ_CONTROL)
#define MASK_FILE_GENERIC_WRITE (MASK_FILE_WRITE_DATA| MASK_FILE_APPEND_DATA| MASK_FILE_WRITE_ATTRIBUTES| MASK_FILE_WRITE_EA| MASK_SYNCHRONIZE| MASK_READ_CONTROL)
#define MASK_FILE_GENERIC_READ (MASK_FILE_READ_DATA| MASK_FILE_READ_ATTRIBUTES| MASK_FILE_READ_EA| MASK_SYNCHRONIZE| MASK_READ_CONTROL)
#define MASK_FILE_LIST_DIRECTORY 0x00000001 /* #define This value indicates the right to enumerate the contents of the directory.*/
#define MASK_FILE_ADD_FILE 0x00000002 /* This value indicates the right to create a file under the directory.*/
#define MASK_FILE_ADD_SUBDIRECTORY 0x00000004 /* This value indicates the right to add a sub-directory under the directory.*/
#define MASK_FILE_READ_EA 0x00000008 /* This value indicates the right to read the extended attributes of the directory.*/
#define MASK_FILE_WRITE_EA 0x00000010 /* This value indicates the right to write or change the extended attributes of the directory.*/
#define MASK_FILE_TRAVERSE 0x00000020 /* This value indicates the right to traverse this directory if the server enforces traversal checking.*/
#define MASK_FILE_DELETE_CHILD 0x00000040 /* This value indicates the right to delete the files and directories within this directory.*/
#define MASK_FILE_READ_ATTRIBUTES 0x00000080  /* This value indicates the right to read the attributes of the directory.*/
#define MASK_FILE_WRITE_ATTRIBUTES 0x00000100 /* This value indicates the right to change the attributes of the directory.*/
#define MASK_DELETE 0x00010000 /* This value indicates the right to delete the directory.*/
#define MASK_READ_CONTROL 0x00020000 /* This value indicates the right to read the security descriptor for the directory.*/
#define MASK_WRITE_DAC 0x00040000 /* This value indicates the right to change the DACL in the security descriptor for the directory. For the DACL data structure*/
#define MASK_WRITE_OWNER 0x00080000 /* This value indicates the right to change the owner in the security descriptor for the directory.*/
#define MASK_SYNCHRONIZE 0x00100000 /* This value SHOULD NOT be used by the sender and MUST be ignored by the receiver.*/
#define MASK_ACCESS_SYSTEM_SECURITY 0x01000000 /* This value indicates the right to read or change the SACL in the security descriptor for the directory. For the SACL data structure*/
#define MASK_DIR_GENERIC_EXECUTE (MASK_FILE_READ_ATTRIBUTES| MASK_FILE_TRAVERSE| MASK_SYNCHRONIZE| MASK_READ_CONTROL)
#define MASK_DIR_GENERIC_WRITE (MASK_FILE_ADD_FILE| MASK_FILE_ADD_SUBDIRECTORY| MASK_FILE_WRITE_ATTRIBUTES| MASK_FILE_WRITE_EA| MASK_SYNCHRONIZE| MASK_READ_CONTROL)
#define MASK_DIR_GENERIC_READ (MASK_FILE_LIST_DIRECTORY| MASK_FILE_READ_ATTRIBUTES| MASK_FILE_READ_EA| MASK_SYNCHRONIZE| MASK_READ_CONTROL)

#define MAX_NUM_OPLOCK_OPEN_FILES           ((UD_FS_NUMSERVERFILEOPEN * 3) / 4)
#define MAX_NUM_OPLOCK_OPEN_UNIQUE_FILES    ((UD_FS_NUMSERVERFILENAMES * 3) / 4)



/*====================================================================
 * PURPOSE: Perform Create processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN user - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Create command.
 *====================================================================
 */

NQ_UINT32 csSmb2OnCreate(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    NQ_UINT32 impresonalizationLevel;   /* o for anonymnous, 1 for a user */
    CSCreateParams params;              /* parameters for common Create processing */
    NQ_UINT16 nameOffset;               /* offset to the file name */
    NQ_UINT16 nameLen;                  /* name length */
    NQ_UINT32 contextOffset;            /* create context offset */
    NQ_UINT32 contextLen;               /* create context length */
    NQ_STATIC NQ_WCHAR fileName[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)]; /* buffer for composing the filename */
    NQ_UINT32 returnValue;              /* value to return */
    NQ_BOOL callCommon = TRUE;          /* true - to call common processing */
    NQ_INT i;                           /* just a counter */
    NQ_COUNT nameLenChars;              /* name length in characters */
    NQ_BYTE oplockLevel;                /* requested oplock level */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;        /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    NQ_STATIC NQ_TCHAR printFileName[CM_BUFFERLENGTH(NQ_TCHAR, 21)];/* print filename */
    NQ_STATIC NQ_CHAR noPrintName[] = "[Name Not Available]";
#endif /* UD_CS_INCLUDERPC_SPOOLSS */
    CSName *pName;                      /* pointer to name slot */
    
    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before = FALSE;
    eventInfo.rid = csGetUserRid(user);
    eventInfo.tid = tree->tid;
    eventInfo.fileName = NULL;
   	eventInfo.access = 0;
#endif
    /* parse requests */
    cmBufferReaderSkip(reader, 1); /* security flags - unused in the tprotocol */
    cmBufferReadByte(reader, &oplockLevel); /* oplock level */
    cmBufferReadUint32(reader, &impresonalizationLevel); 
    cmBufferReaderSkip(reader, 8 + 8); /* create flags + reserved  - unused */
    cmBufferReadUint32(reader, &params.desiredAccess); 
    cmBufferReadUint32(reader, &params.fileAttributes); 
    cmBufferReadUint32(reader, &params.sharedAccess); 
    cmBufferReadUint32(reader, &params.disposition); 
    cmBufferReadUint32(reader, &params.createOptions); 

    LOGMSG(CM_TRC_LEVEL_MESS_SOME, "desired access %x, attrib: %x, shared: %x, disp: %x, cr.options: %x", params.desiredAccess,params.fileAttributes,params.sharedAccess,params.disposition,params.createOptions);

    cmBufferReadUint16(reader, &nameOffset); 
    cmBufferReadUint16(reader, &nameLen); 
    cmBufferReadUint32(reader, &contextOffset); 
    cmBufferReadUint32(reader, &contextLen); 
    nameLenChars = nameLen/sizeof(NQ_WCHAR);
    if (nameLenChars > UD_FS_FILENAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "File name too long: %d", nameLenChars);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_OBJECT_NAME_INVALID;
    }

    /* parse contexts */
    params.context.flags = 0;
    cmBufferReaderSetPosition(reader, in->_start + contextOffset);
    while (contextLen > 0)
    {
        NQ_UINT32 nextOffset;   /* next entry offset */
        NQ_BYTE * curPos;       /* current entry start position */
        NQ_UINT16 nameOffset;   /* context name offset */
        NQ_UINT16 nameLen;      /* context name length */
        NQ_UINT16 dataOffset;   /* context data offset */
        NQ_UINT32 dataLen;      /* context data length */
        const NQ_CHAR * pName;        /* context name pointer */

        curPos = cmBufferReaderGetPosition(reader);

        cmBufferReadUint32(reader, &nextOffset);
        cmBufferReadUint16(reader, &nameOffset);
        cmBufferReadUint16(reader, &nameLen);
        cmBufferReaderSkip(reader, 2);            /* reserved */
        cmBufferReadUint16(reader, &dataOffset);
        cmBufferReadUint32(reader, &dataLen);
        pName = (const NQ_CHAR*) curPos + nameOffset;
        for (i = 0; i < sizeof(contextDescriptors)/sizeof(contextDescriptors[0]); i++)
        {
            if (0 == syStrncmp(contextDescriptors[i].name, pName, nameLen))
            {
                LOGMSG(CM_TRC_LEVEL_MESS_SOME, "context: %s", contextDescriptors[i].name);
                cmBufferReaderSetPosition(reader, curPos + dataOffset);
                callCommon &= contextDescriptors[i].parser(reader, dataLen, &params.context);
                params.context.flags |= contextDescriptors[i].flag;
            }
        }
        if (nextOffset == 0)
            contextLen = 0;
        else
            cmBufferReaderSetPosition(reader, curPos + nextOffset);
    }

    /* normalize file name:
           make name null-terminated temporary, localize and revert back
        */
    cmWStrncpy(fileName, (const NQ_WCHAR *)(in->_start + nameOffset), nameLenChars); 
    fileName[nameLenChars] = 0;  /* force null-terminated */

    params.fileName = cmCifsNtohFilename(tree->share->map, (NQ_TCHAR*)fileName, TRUE);
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.access = params.desiredAccess;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    if (NULL == params.fileName)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.fileName = NULL;
        eventInfo.access = 0;
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_CREATE,
            user->name,
            user->ip,
            SMB_STATUS_OBJECT_NAME_INVALID,
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal filename");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_OBJECT_NAME_INVALID;
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = params.fileName;
#endif /* UD_NQ_INCLUDEEVENTLOG */

#ifdef UD_CS_INCLUDERPC_SPOOLSS
    /* create file name for print file */
    if (tree->share->isPrintQueue)
    {
        cmAnsiToTchar(printFileName, noPrintName);
        params.fileName = printFileName;
    }
#endif /* UD_CS_INCLUDERPC_SPOOLSS */

    /* fill more parameters */
    params.pid = in->pid;
    params.share = tree->share;
    params.tid = (CSTid)in->tid;
    params.uid = user->uid;
    params.unicodeRequired = TRUE;
    params.user = user;

    /* Fix "create options". For an existing file Win SMB2 does not bother to set directory/file 
       flags. Since NQ common SMB1/2 processing checks those bits we need to fill up this gap */
/*    if (csCheckFile(tree->share, params.fileName, user->preservesCase))
    {
        SYFileInformation info;

        if (0 != csGetFileInformationByName(tree->share, params.fileName, &info))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to get file info");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_OBJECT_NAME_INVALID;
        }
        params.createOptions |= (info.attributes & SMB_ATTR_DIRECTORY)? 
            SMB_NTCREATEANDX_DIRECTORY : SMB_NTCREATEANDX_NONDIRECTORY;
        params.createOptions |= SMB_NTCREATEANDX_NONDIRECTORY;
    }
*/

    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "create for file: %s", cmTDump(params.fileName));
    /* call common processing */
    returnValue = 0;
    if (callCommon)
    {
        returnValue = csCreateCommonProcessing(&params);
        if (0 != returnValue && SMB_STATUS_SHARING_VIOLATION != returnValue)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "failed, value 0x%x", returnValue);
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return returnValue;
        }
#ifdef UD_CS_INCLUDEPERSISTENTFIDS 
    if (0 == returnValue)
        params.file->durableFlags = 0;
#endif
    }

    if (0 == returnValue)
    {
        /* perform contexts */
        for (i = 0; i < sizeof(contextDescriptors)/sizeof(contextDescriptors[0]); i++)
        {
            if (contextDescriptors[i].flag & params.context.flags && NULL != contextDescriptors[i].performer)
            {
                returnValue = contextDescriptors[i].performer(&params, &params.context);
                if (0 != returnValue)
                {
                    csReleaseFile(params.file->fid);
                    LOGERR(CM_TRC_LEVEL_ERROR, "failed, value 0x%x", returnValue);
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return returnValue;
                }
            }
        }
    }
    else
    {
        /* create fake file for oplock check */
        pName = csGetNameByName(params.fileName);
        if (NULL == pName)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_CREATE,
                user->name,
                user->ip,
                csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror),
                (const NQ_BYTE*)&eventInfo
            );
#endif /* UD_NQ_INCLUDEEVENTLOG */
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to get name slot pointer");   
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_UNSUCCESSFUL;
        }
        params.file = csGetNewFile(tree, pName, 0);
        if (NULL == params.file)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "No more file slots", returnValue);
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_NO_MORE_ENTRIES;
        }
        params.file->isPipe = FALSE;
#ifdef UD_CS_INCLUDERPC_SPOOLSS
        params.file->isPrint = FALSE;
#endif
        params.file->nid = pName->nid;
    }
    /* check for oplock break */
    if ((oplockLevel != SMB2_OPLOCK_LEVEL_NONE) && csBreakCheck(&params) == TRUE)
    {
        CSFile *pFile;
		 NQ_UINT32 asyncId = 0;     /* generated Async ID */
        /* send interim response */
        pFile = params.file;

        asyncId = csSmb2SendInterimResponse(in);
        if (0 == asyncId)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "error sending interim create response");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_INVALID;
        }
        pFile->breakContext.prot.smb2.aid.low = asyncId;
        pFile->breakContext.prot.smb2.aid.high = 0;
        pFile->breakContext.status = NQ_SUCCESS;
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_NORESPONSE;
    }
    else
    {
        if (SMB_STATUS_SHARING_VIOLATION == returnValue)
            csReleaseFile(params.file->fid);
    }
    if (SMB_STATUS_SHARING_VIOLATION == returnValue)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_CREATE,
            user->name,
            user->ip,
            SMB_STATUS_SHARING_VIOLATION,
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return returnValue;
    }

    /* save fid */
    cs2ParseFid(&params.file->fid);

    /* pack response */
    cmBufferWriteUint16(writer, 89);    /* structure size */
    
    /* grant oplock if required */
#ifdef UD_CS_INCLUDERPC 
    if (params.file->isPipe 
#ifdef UD_CS_INCLUDERPC_SPOOLSS
        || params.file->isPrint
#endif /*UD_CS_INCLUDERPC_SPOOLSS */
        )
    {
        cmBufferWriteByte(writer, SMB2_OPLOCK_LEVEL_NONE); 
    }
    else
#endif /* UD_CS_INCLUDERPC */   
    {
        if ((pName = csGetNameByNid(params.file->nid)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to get name slot pointer");   
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_UNSUCCESSFUL;
        }

		if (oplockLevel != SMB2_OPLOCK_LEVEL_NONE)
		{
            if (params.file->isDirectory || pName->wasOplockBroken)
            {
                oplockLevel = SMB2_OPLOCK_LEVEL_NONE;
            }
            else
            {
                if (csGetFilesCount() > MAX_NUM_OPLOCK_OPEN_FILES ||
                    csGetUniqueFilesCount() > MAX_NUM_OPLOCK_OPEN_UNIQUE_FILES)
                {
                    oplockLevel = SMB2_OPLOCK_LEVEL_NONE;
                }
                else
                {
        			if (0 != csGetFileInformationByName(tree->share, params.fileName, &params.fileInfo
#ifdef UD_NQ_INCLUDEEVENTLOG
        					,user
#endif /* UD_NQ_INCLUDEEVENTLOG */
                        	))
        			{
        				LOGERR(CM_TRC_LEVEL_ERROR, "Unable to get file info");
        				LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        				return SMB_STATUS_OBJECT_NAME_INVALID;
        			}

                    /* we grant LEVEL II oplock for readonly file */
        		    oplockLevel = (params.fileInfo.attributes & SY_ATTR_READONLY) ? SMB2_OPLOCK_LEVEL_NONE : SMB2_OPLOCK_LEVEL_BATCH;
                }
            }
		}
        cmBufferWriteByte(writer, oplockLevel);
        params.file->oplockGranted = oplockLevel != SMB2_OPLOCK_LEVEL_NONE;
        params.file->breakContext.socket = csDispatchGetSocket();
        params.file->breakContext.isSmb2 = TRUE;
    }
 
    cmBufferWriteByte(writer, 0);       /* reserved */
    cmBufferWriteUint32(writer, params.takenAction);
    csWriteFileTimes(&params.fileInfo, csGetNameByNid(params.file->nid), cmBufferWriterGetPosition(writer));
    cmBufferWriterSetPosition(writer, cmBufferWriterGetPosition(writer) + 32);
    cmBufferWriteUint32(writer, params.fileInfo.allocSizeLow);  /* allocation size */
    cmBufferWriteUint32(writer, params.fileInfo.allocSizeHigh);
    cmBufferWriteUint32(writer, params.fileInfo.sizeLow);       /* EOF */
    cmBufferWriteUint32(writer, params.fileInfo.sizeHigh);
    cmBufferWriteUint32(writer, params.fileInfo.attributes);
    cmBufferWriteUint32(writer, 0);                             /* reserved2 */
    cmBufferWriteUint16(writer, params.file->fid);              /* FID */
    cmBufferWriteZeroes(writer, 14);                            /* FID */

    /* write contexts data */
    {
        CMBufferWriter cwriter;  /* contexts writer */

        cmBufferWriterBranch(writer, &cwriter, 8);
        cmBufferWriteUint32(writer, (NQ_UINT16)cmSmb2HeaderGetWriterOffset(out, &cwriter)); /* offset to contexts */ 
        cmBufferWriteUint32(writer, cs2PackCreateContexts(&cwriter, &params.context));      /* contexts length */
        cmBufferWriterSync(writer, &cwriter);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

/*====================================================================
 * PURPOSE: Security Descriptor Context parser
 *--------------------------------------------------------------------
 * PARAMS:  IN reader - request reader pointing to the context data
 *               IN len - context data length
 *               IN/OUT context - pointer to the create context
 *
 * RETURNS: TRUE to call common processing, FALSE to skip
 *====================================================================
 */
static NQ_BOOL parseSecd(CMBufferReader * reader, NQ_UINT32 len, CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    context->sdData = cmBufferReaderGetPosition(reader);
    context->sdLen = (NQ_COUNT)len;
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return TRUE;
}

/*====================================================================
 * PURPOSE: Durable ID Request Context parser
 *--------------------------------------------------------------------
 * PARAMS:  IN reader - request reader pointing to the context data
 *               IN len - context data length
 *               IN/OUT context - pointer to the create context
 *
 * RETURNS: TRUE to call common processing, FALSE to skip
 *====================================================================
 */
static NQ_BOOL parseDhnq(CMBufferReader * reader, NQ_UINT32 len, CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return TRUE;
}

/*====================================================================
 * PURPOSE: Durable ID Re-open Context parser
 *--------------------------------------------------------------------
 * PARAMS:  IN reader - request reader pointing to the context data
 *               IN len - context data length
 *               IN/OUT context - pointer to the create context
 *
 * RETURNS: TRUE to call common processing, FALSE to skip
 *====================================================================
 */
static NQ_BOOL parseDhnc(CMBufferReader * reader, NQ_UINT32 len, CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    context->durableReopen = cmBufferReaderGetPosition(reader);
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return FALSE;
}

/*====================================================================
 * PURPOSE: Allocation SIze Context parser
 *--------------------------------------------------------------------
 * PARAMS:  IN reader - request reader pointing to the context data
 *               IN len - context data length
 *               IN/OUT context - pointer to the create context
 *
 * RETURNS: TRUE to call common processing, FALSE to skip
 *====================================================================
 */
static NQ_BOOL parseAlsi(CMBufferReader * reader, NQ_UINT32 len, CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    cmBufferReadUint64(reader, &context->allocSize);
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return TRUE;
}

/*====================================================================
 * PURPOSE: Maximal Access Context parser
 *--------------------------------------------------------------------
 * PARAMS:  IN reader - request reader pointing to the context data
 *               IN len - context data length
 *               IN/OUT context - pointer to the create context
 *
 * RETURNS: TRUE to call common processing, FALSE to skip
 *====================================================================
 */
static NQ_BOOL parseMxac(CMBufferReader * reader, NQ_UINT32 len, CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return TRUE;
}

/*====================================================================
 * PURPOSE: Maximal Access Context packer
 *--------------------------------------------------------------------
 * PARAMS:  OUT writer - response pointing to the context data
 *               IN params - pointer to common Create parameters
 *               IN context - pointer to the create context
 *
 * RETURNS: entry size or zero when entry should be skipped
 *====================================================================
 */

static NQ_UINT32 packMxac(CMBufferWriter * writer,  CSCreateParams * params, const CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    cmBufferWriteUint32(writer, SMB_STATUS_NOT_SUPPORTED);
    cmBufferWriteUint32(writer, 0);
/*    cmBufferWriteUint32(writer, 0);
    cmBufferWriteUint32(writer, 0x001e01ff);*/
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return sizeof(NQ_UINT32) * 2;
}

/*====================================================================
 * PURPOSE: Duarble ID Query Context packer
 *--------------------------------------------------------------------
 * PARAMS:  OUT writer - response pointing to the context data
 *               IN params - pointer to common Create parameters
 *               IN context - pointer to the create context
 *
 * RETURNS: entry size or zero when entry should be skipped
 *====================================================================
 */
#ifdef UD_CS_INCLUDEPERSISTENTFIDS
#if 0
static NQ_UINT32 packDhnq(CMBufferWriter * writer,  CSCreateParams * params, const CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    cmBufferWriteUint16(writer, params->file->fid);
    cmBufferWriteUint16(writer, 0);
    cmBufferWriteUint32(writer, 0);
    cmBufferWriteUint32(writer, 0);
    cmBufferWriteUint32(writer, 0);
    /* undocumented 16 bytes of zeroes */
    cmBufferWriteUint32(writer, 0);
    cmBufferWriteUint32(writer, 0);
    cmBufferWriteUint32(writer, 0);
    cmBufferWriteUint32(writer, 0);
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return 16 + 16;
}
#endif
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */

/*====================================================================
 * PURPOSE: Allocation size performer
 *--------------------------------------------------------------------
 * PARAMS:  IN params - pointer to common Create parameters
 *               IN context - pointer to the create context
 *
 * RETURNS: entry size or zero when entry should be skipped
 *====================================================================
 */
static NQ_UINT32 performAlsi(CSCreateParams * params, const CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    params->fileInfo.allocSizeLow = context->allocSize.low;
    params->fileInfo.allocSizeHigh = context->allocSize.high;
    csSetFileInformation(params->file, params->fileName, &params->fileInfo);
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return 0;
}

/*====================================================================
 * PURPOSE: Query durable handle performer
 *--------------------------------------------------------------------
 * PARAMS:  IN params - pointer to common Create parameters
 *               IN context - pointer to the create context
 *
 * RETURNS: entry size or zero when entry should be skipped
 *====================================================================
 */
#ifdef UD_CS_INCLUDEPERSISTENTFIDS
/*
static NQ_UINT32 performDhnq(CSCreateParams * params, const CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    params->file->durableFlags = CS_DURABLE_REQUIRED; 
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return 0;
}
*/
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */

/*====================================================================
 * PURPOSE: Set SD performer
 *--------------------------------------------------------------------
 * PARAMS:  IN params - pointer to common Create parameters
 *               IN context - pointer to the create context
 *
 * RETURNS: entry size or zero when entry should be skipped
 *====================================================================
 */
static NQ_UINT32 performSecd(CSCreateParams * params, const CSCreateContext * context)
{
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    if (params->disposition == SMB_NTCREATEANDX_FILECREATE || params->disposition == SMB_NTCREATEANDX_FILEOVERWRITE)
    {
        if (NQ_SUCCESS != sySetSecurityDescriptor(params->file->file, 0, context->sdData, context->sdLen))
        {
            LOGERR(CM_TRC_LEVEL_ERROR,"Unable to save security descriptor");
            LOGFE(CM_TRC_LEVEL_MESS_SOME);
            return csErrorGetLast();
        }
    }
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return 0;
}

/*====================================================================
 * PURPOSE: Re-open durable handle performer
 *--------------------------------------------------------------------
 * PARAMS:  IN params - pointer to common Create parameters
 *          IN context - pointer to the create context
 *
 * RETURNS: entry size or zero when entry should be skipped
 *====================================================================
 */
#ifdef UD_CS_INCLUDEPERSISTENTFIDS
static NQ_UINT32 performDhnc(CSCreateParams * params, const CSCreateContext * context)
{
    CSFid fid;                  /* reopen fid */
    
    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    fid = *(CSFid*)context->durableReopen;
    params->file = csGetFileByFid(fid, params->tid, params->uid);
    if (NULL == params->file)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to reconnect: fid 0x%x not found", fid);
        LOGFE(CM_TRC_LEVEL_MESS_SOME);
        return SMB_STATUS_INVALID_HANDLE;
    }
    if (NQ_SUCCESS != csGetFileInformation(params->file, params->fileName, &params->fileInfo))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to query file info for: %s (fid=0x%x", cmTDump(params->fileName), fid);
        LOGFE(CM_TRC_LEVEL_MESS_SOME);
    }
    params->takenAction = SMB_OPEN2_DOOPEN;
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return 0;
}
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */

/*====================================================================
 * PURPOSE: Convert Posix access mask into NT access mask
 *--------------------------------------------------------------------
 * PARAMS:  IN pFile - pointer to the file structure 
 *
 * RETURNS: NT access mask
 *====================================================================
 */
#if 0
static NQ_UINT32 posixAccesstoNtAccess(const CSFile * pFile)
{
    NQ_UINT32 result = 0;   /* NT access mask */
    NQ_UINT32 access = pFile->access;

    LOGFB(CM_TRC_LEVEL_MESS_SOME);
    if (access == SMB_ACCESS_S_COMPATIBILITY)
    {
        LOGFE(CM_TRC_LEVEL_MESS_SOME);
        return 0x00000003;      /* read & write */
    }
    if (pFile->isDirectory)
    {
        if (access & SMB_ACCESS_A_WRITE)
            result |= MASK_DIR_GENERIC_WRITE;
        if (access & SMB_ACCESS_A_EXECUTE)
            result |= MASK_DIR_GENERIC_EXECUTE;
        if (access & SMB_ACCESS_A_READWRITE)
            result |= MASK_DIR_GENERIC_READ | MASK_DIR_GENERIC_WRITE;
        if (access & SMB_ACCESS_A_DELETE)
            result |= MASK_DELETE;
        if (access & SMB_ACCESS_A_FCB)
            result |= MASK_DIR_GENERIC_READ | MASK_DIR_GENERIC_WRITE | MASK_DIR_GENERIC_EXECUTE | MASK_DELETE;
    }
    else
    {
        if (access & SMB_ACCESS_A_WRITE)
            result |= MASK_FILE_GENERIC_WRITE;
        if (access & SMB_ACCESS_A_EXECUTE)
            result |= MASK_FILE_GENERIC_EXECUTE;
        if (access & SMB_ACCESS_A_READWRITE)
            result |= MASK_FILE_GENERIC_READ | MASK_FILE_GENERIC_WRITE;
        if (access & SMB_ACCESS_A_DELETE)
            result |= MASK_DELETE;
        if (access & SMB_ACCESS_A_FCB)
            result |= MASK_FILE_GENERIC_READ | MASK_FILE_GENERIC_WRITE | MASK_FILE_GENERIC_EXECUTE | MASK_DELETE;
    }
    if (0 == result) 
        result |= MASK_DIR_GENERIC_READ;
    LOGFE(CM_TRC_LEVEL_MESS_SOME);
    return result;
}
#endif /* 0 */

NQ_UINT32
cs2PackCreateContexts(CMBufferWriter *writer, CSCreateContext *context)
{
    NQ_UINT32 contextLen = 0;
    NQ_INT i;       
    NQ_BYTE * nextOffsetPtr = 0;        /* pointer to the next offset field in contexts */
    NQ_BYTE * contextOffsetPtr;         /* pointer to create context offset in response */

    TRCB();

    contextOffsetPtr = cmBufferWriterGetPosition(writer) - 8;

    /* pack contexts */
    for (i = 0; i < sizeof(contextDescriptors)/sizeof(contextDescriptors[0]); i++)
    {
        if (contextDescriptors[i].flag & context->flags && NULL != contextDescriptors[i].packer)
        {
            NQ_UINT16 nameLen;
            NQ_UINT32 dataLen;
            NQ_BYTE * dataLenPtr;
            NQ_UINT16 allignedNameLen;
            NQ_BYTE * tempPtr;                  /* teporary pointer in the writer */
            
            nextOffsetPtr = cmBufferWriterGetPosition(writer);
            cmBufferWriterSkip(writer, 4);  /* skip next */
            cmBufferWriteUint16(writer, 0x10);  /* name offset */
            nameLen = (NQ_UINT16)syStrlen(contextDescriptors[i].name);
            cmBufferWriteUint16(writer, nameLen);  /* name length */
            allignedNameLen = (NQ_UINT16)((nameLen + 7) & ~7);

            cmBufferWriteUint16(writer, 0);  /* reserved */
            cmBufferWriteUint16(writer, (NQ_UINT16)(0x10 + allignedNameLen));  /* data ofset */
            dataLenPtr = cmBufferWriterGetPosition(writer);
            cmBufferWriterSkip(writer, 4);  /* skip data length */

            cmBufferWriteBytes(writer, (const NQ_BYTE *)contextDescriptors[i].name, nameLen);

            cmBufferWriterSetPosition(writer, nextOffsetPtr + 0x10 + allignedNameLen);
            dataLen = contextDescriptors[i].packer(writer, NULL, context);
            contextLen += dataLen + 0x10 + allignedNameLen;
            cmBufferWriterAlign(writer, contextOffsetPtr, 8);
            tempPtr = cmBufferWriterGetPosition(writer);
            cmBufferWriterSetPosition(writer, nextOffsetPtr);
            cmBufferWriteUint32(writer, (NQ_UINT32)(tempPtr - nextOffsetPtr));
            cmBufferWriterSetPosition(writer, dataLenPtr);
            cmBufferWriteUint32(writer, dataLen);
            cmBufferWriterSetPosition(writer, tempPtr);
        }
    }

    if (contextLen != 0)
    {
        cmBufferWriterSetPosition(writer, nextOffsetPtr);
        cmBufferWriteUint32(writer, 0);     /* last next offset */
        cmBufferWriterSetPosition(writer, cmBufferWriterGetStart(writer)+ contextLen);
    }
    TRC("contextLen: %d", contextLen);
    TRCE();
    return contextLen;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

