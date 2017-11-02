/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RPC functions
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 13-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/
#include "csrapfnc.h"
#include "csdataba.h"
#include "csutils.h"
#include "csparams.h"
#include "cstransa.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements RAP funtions over the named pipe subprotocol

   The csPipeRpc function is a named PIPE subcommand of the TRANSACTION command
   This function is also a dispatcher of the pipe command. It calls an appropriate RAP
   function.

   A RAP function parses parameters and composes the response (both parameters and data)
   using symbolic "signatures" provided by the callee. For this purpose it uses three
   local functions processing one signature position in a time.
 */

/*
    Static functions and data
    -------------------------
 */

/* Beginning of packed structures definition */

#include "sypackon.h"

typedef SY_PACK_PREFIX struct
{
    NQ_CHAR name[13];
    NQ_CHAR pad;
    NQ_SUINT16 type;
    NQ_SUINT32 descriptionPointer;
} SY_PACK_ATTR
ShareInformation;

typedef SY_PACK_PREFIX struct
{
    NQ_CHAR name[16];
} SY_PACK_ATTR
ServerInformation0;

typedef SY_PACK_PREFIX struct
{
    NQ_CHAR name[16];
    NQ_CHAR versionMajor;
    NQ_CHAR versionMinor;
    NQ_SUINT32 type;
    NQ_SUINT32 commentPointer;
} SY_PACK_ATTR
ServerInformation1;

typedef SY_PACK_PREFIX struct
{
    NQ_CHAR name[13];
} SY_PACK_ATTR
ShareInformation0;

typedef SY_PACK_PREFIX struct
{
    NQ_CHAR name[13];
    NQ_CHAR pad;
    NQ_SUINT16 type;
    NQ_SUINT32 commentPointer;
} SY_PACK_ATTR
ShareInformation1;

typedef SY_PACK_PREFIX struct
{
    NQ_CHAR name[13];
    NQ_CHAR pad;
    NQ_SUINT16 type;
    NQ_SUINT32 commentPointer;
    NQ_SUINT16 permissions;
    NQ_SUINT16 maxUses;
    NQ_SUINT16 currentUses;
    NQ_SUINT32 path;
    NQ_SUINT16 password[9];
    NQ_SUINT16 pad2;
} SY_PACK_ATTR
ShareInformation2;

typedef SY_PACK_PREFIX struct {
    NQ_SUINT32 computername;
    NQ_SUINT32 username;
    NQ_SUINT32 langroup;
    NQ_SBYTE vermajor;
    NQ_SBYTE verminor;
    NQ_SUINT32 logon_domain;
    NQ_SUINT32 otherdomains;
} SY_PACK_ATTR
WorkstationInformation;

#include "sypackof.h"

/* End of packed structures definition */

/* parameter parsing: also converts to the host byte order */

static
void
parseParameter(
    const NQ_CHAR** signature, /* double pointer to the current place in the signature */
    const NQ_BYTE** paramList, /* double pointer to the current place in the param list */
    void* parameter         /* buffer for the next parameter */
    );

/* response parameter composition: also converts to the network byte order */

void
writeResponseParameter(
    const NQ_CHAR** signature,     /* double pointer to the current place in the signature */
    NQ_BYTE** responseData,        /* double pointer to the current place in the response data */
    const void* value              /* next response value */
    );

/* response data composition: also converts to the network byte order */

void
writeResponseData(
    const NQ_CHAR** signature,     /* double pointer to the current place in the signature */
    NQ_BYTE** responseData,        /* double pointer to the current place in the response data */
    const void* value           /* next response value */
    );

/* API function descriptor */

typedef struct _ApiDescriptor
{
    NQ_UINT apiNumber;              /* function (API) number */
    NQ_BOOL anonymousAllowed;       /* TRUE when this call is allowed for anonymous user */
    const NQ_CHAR *paramsSignature;    /* parameters signature */
    const NQ_CHAR *dataSignature;      /* output data signature */
    NQ_UINT16 (*function)(const struct _ApiDescriptor*, const NQ_BYTE*, const NQ_BYTE*, NQ_UINT16*, NQ_BYTE**, NQ_UINT);
                                    /* function, performing the call */
} ApiDescriptor;

/* prototypes for the API calls */

static NQ_UINT16 apiNetShareEnum(const ApiDescriptor*, const NQ_BYTE*, const NQ_BYTE*, NQ_UINT16*, NQ_BYTE**, NQ_UINT);
static NQ_UINT16 apiNetServerGetInfo(const ApiDescriptor*, const NQ_BYTE*, const NQ_BYTE*, NQ_UINT16*, NQ_BYTE**, NQ_UINT);
static NQ_UINT16 apiNetShareGetInfo(const ApiDescriptor*, const NQ_BYTE*, const NQ_BYTE*, NQ_UINT16*, NQ_BYTE**, NQ_UINT);
static NQ_UINT16 apiNetWkstaGetInfo(const ApiDescriptor*, const NQ_BYTE*, const NQ_BYTE*, NQ_UINT16*, NQ_BYTE**, NQ_UINT);

/* the table of API calls */

static const ApiDescriptor functionList[] =
{
    { 0,    FALSE, "WrLeh", "B13BWz",          apiNetShareEnum },
    { 13,   TRUE,  "WrLh",  "B16",             apiNetServerGetInfo },
    { 13,   TRUE,  "WrLh",  "B16BBDz",         apiNetServerGetInfo },
    { 1,    FALSE, "zWrLh", "B13",             apiNetShareGetInfo },
    { 1,    FALSE, "zWrLh", "B13BWz",          apiNetShareGetInfo },
    { 1,    FALSE, "zWrLh", "B13BWzWWWzB9B",   apiNetShareGetInfo },
    { 63,   TRUE,  "WrLh",  "zzzBBzz",         apiNetWkstaGetInfo }
};

/*====================================================================
* PURPOSE: Continue processing TRANSACTION command for a LANMAN PIPE request
  *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to transaction descriptor
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:
 *====================================================================
 */


NQ_UINT32
csRapApiEntry(
    CSTransactionDescriptor* descriptor
    )
{
    NQ_UINT16 apiNumber;            /* RPC API# - code of a server API function */
    const NQ_CHAR* paramsSignature; /* description of the input parameters */
    const NQ_CHAR* dataSignature;   /* description of the function data */
    const NQ_BYTE* paramsData;      /* the input parameters */
    const NQ_BYTE* inputData;       /* auxilliary input data */
    NQ_UINT16 returnValue;          /* function result */
    NQ_UINT i;                      /* just an index */

    TRCB();

    /* the following check is disabled since SAMBA expects RAP over any TID */

    /* check the sent TID in the header - it should be the ID of the IPC$ tree */

    /*    {
        CSTree* pTree;

        pTree = csGetTreeByTid(cmLtoh16(pHeaderOut->tid));
        if (pTree == NULL || pTree->share != pShare)
        {
            TRCERR("\\PIPE\\LANMAN request is not to IPC$");

            TRCE();
            return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRError));
        }
    }*/

    /* find call parameters:
        - API number (the required function)
        - signature of the input parameters
        - signature of the data
        - pointer to the input structure data
     */

    {
        apiNumber = *(NQ_UINT16*)descriptor->paramIn;
        apiNumber = cmLtoh16(apiNumber);
        paramsSignature = (NQ_CHAR*)(descriptor->paramIn + 2);
        dataSignature = paramsSignature + syStrlen(paramsSignature) + 1;
        paramsData = (NQ_BYTE*)dataSignature + syStrlen(dataSignature) + 1;

        TRC3P("API function required: %d, %s, %s", apiNumber, paramsSignature, dataSignature);

        if (descriptor->dataCount == 0)
        {
            inputData = NULL;
        }
        else
        {
            inputData = descriptor->dataIn;
        }
    }

    for (i = 0; i < sizeof(functionList)/sizeof(functionList[0]); i++)
    {
        if (   apiNumber == functionList[i].apiNumber
            && syStrcmp(functionList[i].paramsSignature, paramsSignature) == 0
            && syStrcmp(functionList[i].dataSignature, dataSignature) == 0
           )
        {
            CMCifsRapResponse* rapResponse;     /* casted response */
            NQ_BYTE* pData;                     /* pointer to response data */
            NQ_UINT16 extraParameters;          /* number of extra parameter bytes
                                                   (parameterCount - 4) */
            NQ_UINT16 temp;                     /* calculating temp */
            CSUser* pUser;                      /* pointer to the user descriptor */
            NQ_BYTE* pResponse;                 /* advanced pointer in the response */
            NQ_UINT16* pStatus;                 /* pointer to status */

            pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(descriptor->hdrOut->uid)));
            if (pUser == NULL)
            {
                TRCERR("Unknown UID");
                TRCE();
                return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
            }
/*            if (pUser->isAnonymous && !functionList[i].anonymousAllowed)
            {
                TRCERR("This RAP function is not allowed for Anonymous user");
                TRC1P(" code: %d", apiNumber);
                TRCE();
                return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
            }*/

            rapResponse = (CMCifsRapResponse*)descriptor->pBuf;
            pStatus = (NQ_UINT16*)(rapResponse + 1);
            /*pStatus = (NQ_UINT16*)cmAllignTwo((NQ_BYTE*)pStatus);*/
            pData = (NQ_BYTE*)pStatus + SMB_PIPE_PARAMETERCOUNT;    /* skip status and offset */

            pResponse = pData;
            descriptor->paramOut = (NQ_BYTE*)pStatus;
            extraParameters = 0;

            returnValue = functionList[i].function(
                                &functionList[i],
                                paramsData,
                                inputData,
                                &extraParameters,
                                &pResponse,
                                (NQ_UINT)(CS_MAXBUFFERSIZE - (NQ_UINT)(pData - (NQ_BYTE*)descriptor->hdrOut))
                                );

            pData += extraParameters;
            descriptor->dataOut = pData;

            /* compose the response */

            descriptor->paramCount = (NQ_UINT16)(SMB_PIPE_PARAMETERCOUNT + extraParameters);
            descriptor->setupCount = 0;
            descriptor->dataCount = (NQ_UINT16)(pResponse - pData);
            cmPutUint16(pStatus, cmHtol16(returnValue));
            pStatus++;
            cmPutUint16(pStatus, cmHtol16((NQ_UINT16)((NQ_ULONG)pData & 0xFFFF)));  /* converter word */
            temp = (NQ_UINT16)((NQ_UINT16)(pResponse - (NQ_BYTE*)rapResponse) - sizeof(rapResponse->byteCount));
            cmPutSUint16(rapResponse->byteCount, cmHtol16((NQ_UINT16)temp));

            TRCE();
            return 0;
        }
    }

    TRCERR("Not a registered RPC call ");
    TRCE();
    return csErrorReturn(SMB_STATUS_INVALID_PIPE_STATE, DOS_ERRbadpipe);
}

/*
 *====================================================================
 * PURPOSE: NetShareEnum API function
 *--------------------------------------------------------------------
 * PARAMS:  IN function descriptor for which this function is called
 *          IN input parameters
 *          IN input data (not used)
 *          OUT buffer for the number of extra parameter bytes (in additiona to
 *              4 predefined)
 *          IN/OUT double pointer to output data:
 *              IN  on entry points to the result data buffer
 *              OUT on exit points to the next byte after the result data
 *          IN remaining space in this buffer
 *
 * RETURNS: API return status
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT16
apiNetShareEnum(
    const ApiDescriptor* descriptor,
    const NQ_BYTE* inpParams,
    const NQ_BYTE* inpData,
    NQ_UINT16* extraParameters,
    NQ_BYTE** outData,
    NQ_UINT availableLength
    )
{
    NQ_UINT dataLength;                /* data length to date */
    NQ_UINT16 clientLength;            /* required buffer length */
    NQ_UINT16 tempParameter;           /* placeholder for unused parameters */
    NQ_UINT16 numShares;               /* total number of shares */
    NQ_UINT16 numReturned;             /* number of shares returned */
    CSShare* pShare;                   /* pointer to the next share */
    const NQ_CHAR* paramSignature;     /* "sliding" pointer to parameter signature */
    const NQ_CHAR* dataSignature;      /* "sliding" pointer to data signature */
    NQ_CHAR* pName;                    /* pointer to names in the data buffer */
    NQ_UINT16 i;                       /* just an index */
    NQ_UINT16 returnValue;             /* status to return */
    NQ_UINT16 numSkipped;              /* number of skipped shares with long name */
    NQ_UINT16 numEntries;              /* number of share entries that fit the buffer */

    TRCB();

    /* prepare values */

    *extraParameters = 2*2;        /* two more words in response parameters */

    numShares = (NQ_UINT16)csGetSharesCount();

    /* read parameters */

    paramSignature = descriptor->paramsSignature;

    parseParameter(&paramSignature, &inpParams, &tempParameter);        /* skip */
    parseParameter(&paramSignature, &inpParams, &tempParameter);        /* skip */
    parseParameter(&paramSignature, &inpParams, &clientLength);

    if (clientLength < availableLength)
    {
        availableLength = clientLength;
    }


    /* calculate the number of share entries that may fit the buffer */

    dataLength = *extraParameters;
    numSkipped = 0;

    for (i = 0; i < numShares; i++)
    {
        pShare = csGetShareByIndex(i);

         /* skip if share name is longer than 12 characters */
        if (cmTStrlen(pShare->name) > 12)
        {
            numSkipped++;
            continue;
        }

        dataLength += (NQ_UINT)sizeof(ShareInformation);
        dataLength += (NQ_UINT)cmTStrlen(pShare->description) + 1;
        if (dataLength > availableLength)
            break;
    }

    numEntries = i;
    numReturned = (NQ_UINT16)(numEntries - numSkipped);

    returnValue = ((numReturned == numShares) || (numReturned + numSkipped == numShares))? SMB_RAPSTATUS_NERR_Success : SMB_RAPSTATUS_MORE_DATA;


    /* write response parameters */

    writeResponseParameter(&paramSignature, outData, &numReturned);
    writeResponseParameter(&paramSignature, outData, &numShares);

    /* write data: outData is already advanced to the start of data section */

    pName = (NQ_CHAR*)(*outData + numReturned * sizeof(ShareInformation));

    for (i = 0; i < numEntries; i++)
    {
        NQ_CHAR name[13];      /* share name truncated to 12 characters */
        NQ_UINT16 type;        /* share type */

        pShare = csGetShareByIndex(i);
        if (NULL == pShare)
        {
        	return SMB_RAPSTATUS_ACCESS_DENIED;
        }

         /* skip entry if share name is longer than 12 characters */

        if (cmTStrlen(pShare->name) > 12)
            continue;

        /* copy share name and truncate it if it has more then 12 characters */

        cmTcharToAnsiN(name, pShare->name, 12);
        name[12] = 0;

        /* calculate offset to the name and share type */

        type = SMB_SHARETYPE_DISKTREE;
        if (pShare->ipcFlag)
        {
            type = SMB_SHARETYPE_IPC;
        }
        else if (pShare->isPrintQueue)
        {
            type = SMB_SHARETYPE_PRINTQ;
        }
        else if (pShare->isDevice)
        {
            type = SMB_SHARETYPE_DEVICE;
        }

        /* write share data */

        dataSignature = descriptor->dataSignature;
        writeResponseData(&dataSignature, outData, name);
        writeResponseData(&dataSignature, outData, &name[12]);  /* pad */
        writeResponseData(&dataSignature, outData, &type);
        writeResponseData(&dataSignature, outData, &pName);

        /* write name */

        if (type == SMB_SHARETYPE_IPC || pShare->description == NULL)
        {
            syStrcpy(pName, "");
            pName += syStrlen("") + 1;
        }
        else
        {
            cmTcharToAnsi(pName, pShare->description);
            pName += syStrlen(pName) + 1;
        }
    }

    *outData = (NQ_BYTE*)pName;

    TRCE();
    return returnValue;
}

/*
 *====================================================================
 * PURPOSE: NetServerGetInfo API function
 *--------------------------------------------------------------------
 * PARAMS:  IN function descriptor for which this function is called
 *          IN input parameters
 *          IN input data (not used)
 *          OUT buffer for the number of extra parameter bytes (in additiona to
 *              4 predefined)
 *          IN/OUT double pointer to output data:
 *              IN  on entry points to the result data buffer
 *              OUT on exit points to the next byte after the result data
 *          IN remaining space in this buffer
 *
 * RETURNS: API return status
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT16
apiNetServerGetInfo(
    const ApiDescriptor* descriptor,
    const NQ_BYTE* inpParams,
    const NQ_BYTE* inpData,
    NQ_UINT16* extraParameters,
    NQ_BYTE** outData,
    NQ_UINT availableLength
    )
{
    NQ_UINT16 dataLength;           /* data length to date */
    NQ_UINT16 clientLength;         /* required buffer length */
    NQ_UINT16 detailLevel;          /* level of details */
    const NQ_CHAR* paramSignature;     /* "sliding" pointer to parameter signature */
    const NQ_CHAR* dataSignature;      /* "sliding" pointer to data signature */
    NQ_STATIC NQ_TCHAR serverComment[CM_BUFFERLENGTH(NQ_TCHAR, 100)]; /* server comment buffer */
    NQ_STATIC NQ_CHAR asciiComment[CM_BUFFERLENGTH(NQ_CHAR, 100)];    /* server comment buffer */

    TRCB();

    /* prepare values */

    *extraParameters = 2;   /* one more word in response parameters */

    /* read parameters */

    paramSignature = descriptor->paramsSignature;
    parseParameter(&paramSignature, &inpParams, &detailLevel);
    parseParameter(&paramSignature, &inpParams, &detailLevel);
    parseParameter(&paramSignature, &inpParams, &clientLength);

    /* check buffer size */

    if (clientLength < availableLength)
    {
        availableLength = clientLength;
    }

    dataLength = *extraParameters;
    if (detailLevel == 0)
    {
        dataLength = (NQ_UINT16)(dataLength + sizeof(ServerInformation0));
    }
    else
    {
        dataLength = (NQ_UINT16)(dataLength + sizeof(ServerInformation1));

        /* read server comment from UD */
        udGetServerComment(serverComment);
        cmTcharToAnsi(asciiComment, serverComment);
        dataLength = (NQ_UINT16)(dataLength + syStrlen(asciiComment) + sizeof(NQ_CHAR));
    }

    writeResponseParameter(&paramSignature, outData, &dataLength);

    if (dataLength > availableLength)
    {
        TRCE();
        return SMB_RAPSTATUS_MORE_DATA;
    }

    /* write data: outData is already advanced to the start of the data area */

    {
        CMNetBiosName name;                 /* server name truncated to 16 characters */
        NQ_UINT32 type = csGetHostType();   /* server type */
        NQ_BYTE version0;                   /* for writing versions */
        NQ_BYTE version1;                   /* for writing versions */

        /* copy share name and truncate it if it has more then 12 characters */

        cmNetBiosNameCopy(name, cmNetBiosGetHostNameZeroed());

        /* get server versions */

        version0 = CM_SOFTWAREVERSIONMAJOR;
        version1 = CM_SOFTWAREVERSIONMINOR;

        /* write server data */

        dataSignature = descriptor->dataSignature;

        writeResponseData(&dataSignature, outData, name);
        if (detailLevel > 0)
        {
            NQ_CHAR* pComment;  /* server comment string */

            writeResponseData(&dataSignature, outData, &version0);
            writeResponseData(&dataSignature, outData, &version1);
            writeResponseData(&dataSignature, outData, &type);
            pComment = (NQ_CHAR*)(*outData + 4);
            writeResponseData(&dataSignature, outData, &pComment);
            syStrcpy(pComment, asciiComment);
        }
    }

    *outData += syStrlen(asciiComment) + 1;

    TRCE();
    return SMB_RAPSTATUS_NERR_Success;
}

/*
 *====================================================================
 * PURPOSE: NetShareGetInfo API function
 *--------------------------------------------------------------------
 * PARAMS:  IN function descriptor for which this function is called
 *          IN input parameters
 *          IN input data (not used)
 *          OUT buffer for the number of extra parameter bytes (in additiona to
 *              4 predefined)
 *          IN/OUT double pointer to output data:
 *              IN  on entry points to the result data buffer
 *              OUT on exit points to the next byte after the result data
 *          IN remaining space in this buffer
 *
 * RETURNS: API return status
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT16
apiNetShareGetInfo(
    const ApiDescriptor* descriptor,
    const NQ_BYTE* inpParams,
    const NQ_BYTE* inpData,
    NQ_UINT16* extraParameters,
    NQ_BYTE** outData,
    NQ_UINT availableLength
    )
{
    NQ_UINT dataLength;             /* data length to date */
    NQ_UINT16 clientLength;         /* required buffer length */
    NQ_UINT16 detailLevel;          /* level of details */
    CSShare* pShare;                /* pointer to the next share */
    const NQ_CHAR* paramSignature;     /* "sliding" pointer to parameter signature */
    const NQ_CHAR* dataSignature;      /* "sliding" pointer to data signature */
    NQ_CHAR* pName;                    /* pointer to the required share name */
    NQ_BYTE* dataStart;             /* pointer to the beginning of the data buffer */
    NQ_TCHAR shareNameT[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXSHARELEN)]; /* share name in TCHAR */

    TRCB();

    /* prepare values */

    *extraParameters = 2;        /* one more word in response parameters */

    dataStart = *outData + *extraParameters;    /* start of the data buffer */

    /* read parameters */

    paramSignature = descriptor->paramsSignature;

    parseParameter(&paramSignature, &inpParams, &pName);
    parseParameter(&paramSignature, &inpParams, &detailLevel);
    parseParameter(&paramSignature, &inpParams, &clientLength); /* dummy parsing for R parameter */
    parseParameter(&paramSignature, &inpParams, &clientLength);

    /* find share */

    cmAnsiToTchar(shareNameT, pName);
    if ((pShare = csGetShareByName(shareNameT)) == NULL)
    {
        dataLength = 0;
        writeResponseParameter(&paramSignature, outData, &dataLength);
        TRC1P("Share not found: %s", pName);

        TRCE();
        return SMB_RAPSTATUS_BadTransactConfig;
    }

    /* check buffer size */

    if (clientLength < availableLength)
        availableLength = clientLength;

    dataLength = *extraParameters;

    if (detailLevel == 0)
        dataLength += (NQ_UINT)sizeof(ShareInformation0);
    else if (detailLevel == 1)
        dataLength += (NQ_UINT)sizeof(ShareInformation1);
    else if (detailLevel == 2)
        dataLength += (NQ_UINT)sizeof(ShareInformation2);

    pName = (NQ_CHAR*)(dataStart + dataLength - *extraParameters);  /* place for description */

    if (detailLevel > 0)
        dataLength += (NQ_UINT)cmTStrlen(pShare->description) + 1;

    writeResponseParameter(&paramSignature, outData, &dataLength);

    TRC2P("data length: %0x, available: %0x", dataLength, availableLength);

    if (dataLength > availableLength)
    {
        TRCE();
        return SMB_RAPSTATUS_MORE_DATA;
    }

    /* write data */

    {
        NQ_CHAR name[13];              /* share name truncated to 12 characters */
        NQ_UINT16 type;                /* share type - disk tree or IPC */
        NQ_ULONG offset;                /* "pointer" to description as an offset the data start */
        NQ_UINT16 password = 0;        /* null password */
        NQ_UINT16 permissions = 0x3F;  /* share permission: all but permision change */
        NQ_UINT16 maxUsers;            /* maximum number of users on share */
        NQ_UINT16 currentUsers;        /* connected users */
        NQ_UINT i;                     /* just a counter */
        NQ_TCHAR adminNameT[7];        /* for convering predefined shares into TCHAR */
        NQ_TCHAR ipcNameT[5];          /* for convering predefined shares into TCHAR */

        /* copy share name and truncate it if it has more then 12 characters */

        cmTcharToAnsiN(name, pShare->name, 12);
        name[12] = 0;

        /* calculate offset to the name */

        cmAnsiToTchar(adminNameT, "ADMIN$");
        cmAnsiToTchar(ipcNameT, "IPC$");
        if (    cmTStrcmp(adminNameT, pShare->name) == 0
             || cmTStrcmp(ipcNameT, pShare->name) == 0
           )
        {
            offset = 0L;
            type = 3;           /* interprocess communication */
        }
        else
        {
            offset = (NQ_ULONG)pName;
            type = 0;           /* disk tree */
        }

        /* write share data */

        TRC1P("outdata: %p", *outData);

        dataSignature = descriptor->dataSignature;
        writeResponseData(&dataSignature, outData, name);

        if (detailLevel > 0)
        {
            writeResponseData(&dataSignature, outData, &name[12]);      /* pad */
            writeResponseData(&dataSignature, outData, &type);
            writeResponseData(&dataSignature, outData, &offset);

            /* write share name */

            if (offset != 0)
            {
                cmTcharToAnsi(pName, pShare->description);
                pName += syStrlen(pName) + 1;
            }
            if (detailLevel > 1)
            {
                /* calculate offset to the path name and counters */

                offset = (NQ_ULONG)pName;
                maxUsers = UD_FS_NUMSERVERUSERS;
                currentUsers = (NQ_UINT16)csGetNumberOfShareUsers(pShare);

                /* write more data */

                writeResponseData(&dataSignature, outData, &permissions);
                writeResponseData(&dataSignature, outData, &maxUsers);
                writeResponseData(&dataSignature, outData, &currentUsers);
                writeResponseData(&dataSignature, outData, &offset);
                for (i = 10; i>0; i--)      /* write 10 nulls including the pad */
                {
                    writeResponseData(&dataSignature, outData, &password);
                }

                /* write path name */

                cmTcharToAnsi(pName, pShare->map);
                pName += syStrlen(pName) + 1;
            }
        }
    }

    TRC1P("outdata: %p", *outData);

    *outData = (NQ_BYTE*)pName;

    TRCE();
    return SMB_RAPSTATUS_NERR_Success;
}

/*
 *====================================================================
 * PURPOSE: NetWkstaGetInfo API function
 *--------------------------------------------------------------------
 * PARAMS:  IN function descriptor for which this function is called
 *          IN input parameters
 *          IN input data (not used)
 *          OUT buffer for the number of extra parameter bytes (in additiona to
 *              4 predefined)
 *          IN/OUT double pointer to output data:
 *              IN  on entry points to the result data buffer
 *              OUT on exit points to the next byte after the result data
 *          IN remaining space in this buffer
 *
 * RETURNS: API return status
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT16
apiNetWkstaGetInfo(
    const ApiDescriptor* descriptor,
    const NQ_BYTE* inpParams,
    const NQ_BYTE* inpData,
    NQ_UINT16* extraParameters,
    NQ_BYTE** outData,
    NQ_UINT availableLength
    )
{
    NQ_UINT16 dataLength;              /* data length to date */
    NQ_UINT16 clientLength;            /* required buffer length */
    NQ_UINT16 detailLevel;             /* level of details */
    const NQ_CHAR* paramSignature;     /* "sliding" pointer to parameter signature */
    const NQ_CHAR* dataSignature;      /* "sliding" pointer to data signature */
    NQ_CHAR* pName;                    /* pointer to the next name to write */
    NQ_BYTE* dataStart;                /* pointer to the beginning of the data buffer */
    const NQ_CHAR* hostName;           /* this computer name */
    const NQ_CHAR* domainName;         /* domain name pointer */
    NQ_ULONG hostOffset;                /* offset to host name */
    NQ_ULONG domainOffset;              /* offset to domain name */
    NQ_ULONG otherOffset;               /* offset to other domains name */

    TRCB();

    /* prepare values */

    *extraParameters = 2;        /* one more word in response parameters */
    dataStart = *outData + *extraParameters;    /* start of the data buffer */

    /* read parameters */

    paramSignature = descriptor->paramsSignature;
    parseParameter(&paramSignature, &inpParams, &detailLevel);
    parseParameter(&paramSignature, &inpParams, &clientLength);     /* skip 'r' */
    parseParameter(&paramSignature, &inpParams, &clientLength);

    /* prepare names */

    hostName = cmNetBiosGetHostNameZeroed();
    domainName = cmNetBiosGetDomain()->name;

    /* check buffer size */

    if (clientLength < availableLength)
        availableLength = clientLength;

    dataLength =   (NQ_UINT16)(sizeof(WorkstationInformation)
                 + syStrlen(hostName) + 1
                 + syStrlen(domainName) + 1
                 + 1    /* for other domains as zero string */
                 );

    TRC1P("data length in parameters: %02x", dataLength);

    writeResponseParameter(&paramSignature, outData, &dataLength);

    dataLength = (NQ_UINT16)(dataLength + *extraParameters);

    if (dataLength > availableLength)
    {
        TRCE();
        return SMB_RAPSTATUS_MORE_DATA;
    }

    /* write names after the information structure:
        1) host name
        2) domain name
        3) other domains as an empty string */

    pName = (NQ_CHAR*)(dataStart + sizeof(WorkstationInformation));
    hostOffset = (NQ_ULONG)pName;
    syStrcpy(pName, hostName);

    pName += syStrlen(hostName) + 1;
    domainOffset = (NQ_ULONG)pName;
    syStrcpy(pName, domainName);

    pName += syStrlen(domainName) + 1;
    otherOffset = (NQ_ULONG)pName;
    *pName++ = '\0';                                /* empty "other domains" name */

    /* write structure */

    {
        NQ_BYTE version0;                  /* for writing versions */
        NQ_BYTE version1;                  /* for writing versions */

        /* get server versions */

        version0 = CM_SOFTWAREVERSIONMAJOR;
        version1 = CM_SOFTWAREVERSIONMINOR;

        /* write structure data */

        dataSignature = descriptor->dataSignature;
        writeResponseData(&dataSignature, outData, &hostOffset);
        writeResponseData(&dataSignature, outData, &otherOffset);
        writeResponseData(&dataSignature, outData, &domainOffset);
        writeResponseData(&dataSignature, outData, &version0);
        writeResponseData(&dataSignature, outData, &version1);
        writeResponseData(&dataSignature, outData, &domainOffset);
        writeResponseData(&dataSignature, outData, &otherOffset);
    }

    *outData = (NQ_BYTE*)pName;

    TRCE();
    return SMB_RAPSTATUS_NERR_Success;
}

/*
 *====================================================================
 * PURPOSE: parameter parsing
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT double pointer to the current place in the signature,
 *                 on exit this pointer is advanced to the next character
 *          IN/OUT double pointer to the current place in the parameter list
 *                 on exit this pointer is advanced to the next parameter
 *          OUT buffer for the next parameter
 * RETURNS: NONE
 *
 * NOTES:   also converts to the host byte order
 *====================================================================
 */

static
void
parseParameter(
    const NQ_CHAR** signature,
    const NQ_BYTE** paramList,
    void* parameter
    )
{
    switch (syToupper(**signature))
    {
    case '\0':
        return;
    case 'T':
    case 'L':
    case 'W':
        *(NQ_UINT16*)parameter = cmLtoh16(cmGetUint16(*paramList));
        *paramList += 2;
        break;
    case 'D':
        *(NQ_UINT32*)parameter = cmLtoh32(cmGetUint32(*paramList));
        *paramList += 4;
        break;
    case 'B':
        *(NQ_BYTE*)parameter = **paramList;
        *paramList += sizeof(NQ_BYTE);
        break;
    case 'O':
        break;
    case 'Z':
        *(void**)parameter = (NQ_BYTE*)*paramList;
        *paramList += syStrlen((NQ_CHAR*)*paramList) + 1;
        break;
    case 'F':
        break;
    case 'R':
        break;
    case 'S':
        break;
    default:        /* a counter */
        *paramList += syStrtol(*signature, (NQ_CHAR**)signature, 10);
        return;
    }
    (*signature)++;
}

/*
 *====================================================================
 * PURPOSE: response parameter composition
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT double pointer to the current place in the signature,
 *                 on exit this pointer is advanced to the next character
 *          IN/OUT double pointer to the current place in the response data
 *                 on exit this pointer is advanced to the next value
 *          IN pointer to the next response value
 * RETURNS: NONE
 *
 * NOTES:   writes one value into the response buffer
 *          if the sigmature expired, this function does nothing
 *          also converts to the network byte order
 *====================================================================
 */

void
writeResponseParameter(
    const NQ_CHAR** signature,
    NQ_BYTE** responseData,
    const void* value
    )
{
    switch (syToupper(**signature))
    {
    case '\0':
        return;     /* do not advance the signature */
    case 'G':
        {
            NQ_UINT cnt;

            cnt = (NQ_UINT)syStrtol(*signature + 1, (NQ_CHAR**)signature, 10);
            if (cnt == 0)
            {
                cnt = 1;
            }

            syMemcpy(*responseData, value, cnt);
            *responseData += cnt;
            return;         /* we already advanced the signature */
        }
    case 'E':
    case 'H':
        cmPutUint16(*responseData, cmHtol16(*(NQ_UINT16*)value));
        *responseData += 2;
        break;
    case 'I':
        cmPutUint32(*responseData, cmHtol32(*(NQ_UINT32*)value));
        *responseData += 4;
        break;
    default:
        break;
    }
    (*signature)++;
}

/*
 *====================================================================
 * PURPOSE: response data composition
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT double pointer to the current place in the signature,
 *                 on exit this pointer is advanced to the next character
 *          IN/OUT double pointer to the current place in the response data
 *                 on exit this pointer is advanced to the next value
 *          IN pointer to the next response value
 * RETURNS: NONE
 *
 * NOTES:   writes one value into the response buffer
 *          if the sigmature expired, this function does nothing, thus allowing to
 *          transparently use short and long signatures (in a short signature case
 *          the tail will not be written)
 *          also converts to the network byte order
 *====================================================================
 */

void
writeResponseData(
    const NQ_CHAR** signature,
    NQ_BYTE** responseData,
    const void* value
    )
{

    switch (syToupper(**signature))
    {
    case '\0':
        return;     /* do not advance the signature */
    case 'O':
        *responseData += 4;
        break;
    case 'B':
        {
            NQ_UINT cnt;

            cnt = (NQ_UINT)syStrtol(*signature + 1, (NQ_CHAR**)signature, 10);
            if (cnt == 0)
            {
                cnt = 1;
            }
            syMemcpy(*responseData, value, cnt);
            *responseData += cnt;
            return;         /* we already advanced the signature */
        }
    case 'W':
    case 'N':
        cmPutUint16(*responseData, cmHtol16(*(NQ_UINT16*)value));
        *responseData += 2;
        break;
    case 'D':
    case 'Z':
        cmPutUint32(*responseData, cmHtol32(*(NQ_UINT32*)value));
        *responseData += 4;
        break;
    default:
        break;
    }
    (*signature)++;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

