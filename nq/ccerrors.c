/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#include "ccerrors.h"
#include "ccapi.h"

/* -- Static data and definitions -- */

/* error mapping array: first value is an NQ internal error code, second value is SMB error
   class, the last value is SMB error code */

struct cifsDosErrorMap
{
    NQ_UINT nqError;            /* internal error */
    NQ_UINT32 code;             /* SMB error code */
}

/* SMB in NT format erros mapped on system errors */

static smbDosToSysErrorMap[] =
{
    { NQ_ERR_OK,              0 },

    { NQ_ERR_BADFUNC,            DOS_ERRbadfunc },
    { NQ_ERR_BADFILE,            DOS_ERRbadfile },
    { NQ_ERR_BADPATH,            DOS_ERRbadpath },
    { NQ_ERR_NOFIDS,             DOS_ERRnofids },
    { NQ_ERR_NOACCESS,           DOS_ERRnoaccess },
    { NQ_ERR_BADFID,             DOS_ERRbadfid },
    { NQ_ERR_BADMCB,             DOS_ERRbadmcb },
    { NQ_ERR_NOMEM,              DOS_ERRnomem },
    { NQ_ERR_BADMEM,             DOS_ERRbadmem },
    { NQ_ERR_BADENV,             DOS_ERRbadenv },
    { NQ_ERR_BADFORMAT,          DOS_ERRbadformat },
    { NQ_ERR_BADACCESS,          DOS_ERRbadaccess },
    { NQ_ERR_BADDATA,            DOS_ERRbaddata },
    { NQ_ERR_BADDRIVE,           DOS_ERRbaddrive },
    { NQ_ERR_REMCD,              DOS_ERRremcd },
    { NQ_ERR_DIFFDEVICE,         DOS_ERRdiffdevice },
    { NQ_ERR_NOFILES,            DOS_ERRnofiles },
    { NQ_ERR_BADSHARE,           DOS_ERRbadshare },
    { NQ_ERR_LOCK,               DOS_ERRlock },
    { NQ_ERR_DONTSUPPORTIPC,     DOS_ERRdontsupportipc },
    { NQ_ERR_NOSHARE,            DOS_ERRnoshare },
    { NQ_ERR_FILEXISTS,          DOS_ERRfileexists },
    { NQ_ERR_BADDIRECTORY,       DOS_ERRbaddirectory },
    { NQ_ERR_INSUFFICIENTBUFFER, DOS_ERRinsufficientbuffer },
    { NQ_ERR_INVALIDNAME,        DOS_ERRinvalidname },
    { NQ_ERR_ALREADYEXISTS,      DOS_ERRalreadyexists },
    { NQ_ERR_BADPIPE,            DOS_ERRbadpipe },
    { NQ_ERR_PIPEBUSY,           DOS_ERRpipebusy },
    { NQ_ERR_PIPECLOSING,        DOS_ERRpipeclosing },
    { NQ_ERR_NOTCONNECTED,       DOS_ERRnotconnected },
    { NQ_ERR_MOREDATA,           DOS_ERRmoredata },


    { NQ_ERR_ERROR,              SRV_ERRerror },
    { NQ_ERR_BADPW,              SRV_ERRbadpw },
    { NQ_ERR_ACCESS,             SRV_ERRaccess },
    { NQ_ERR_INVTID,             SRV_ERRinvtid },
    { NQ_ERR_INVNETNAME,         SRV_ERRinvnetname },
    { NQ_ERR_INVDEVICE,          SRV_ERRinvdevice },
    { NQ_ERR_QFULL,              SRV_ERRqfull },
    { NQ_ERR_QTOOBIG,            SRV_ERRqtoobig },
    { NQ_ERR_QEOF,               SRV_ERRqeof },
    { NQ_ERR_INVFID,             SRV_ERRinvfid },
    { NQ_ERR_SMBCMD,             SRV_ERRsmbcmd },
    { NQ_ERR_SRVERROR,           SRV_ERRsrverror },
    { NQ_ERR_FILESPECS,          SRV_ERRfilespecs },
    { NQ_ERR_BADPERMITS,         SRV_ERRbadpermits },
    { NQ_ERR_SETATTRMODE,        SRV_ERRsetattrmode },
    { NQ_ERR_PAUSED,             SRV_ERRpaused },
    { NQ_ERR_MSGOFF,             SRV_ERRmsgoff },
    { NQ_ERR_NOROOM,             SRV_ERRnoroom },
    { NQ_ERR_RMUNS,              SRV_ERRrmuns },
    { NQ_ERR_TIMEOUT,            SRV_ERRtimeout },
    { NQ_ERR_NORESOURCE,         SRV_ERRnoresource },
    { NQ_ERR_TOOMANYUIDS,        SRV_ERRtoomanyuids },
    { NQ_ERR_INVUID,             SRV_ERRinvuid },
    { NQ_ERR_USEMPX,             SRV_ERRusempx },
    { NQ_ERR_USESTD,             SRV_ERRusestd },
    { NQ_ERR_CONTMPX,            SRV_ERRcontmpx },
    { NQ_ERR_NOSUPPORT,          (NQ_UINT32)SRV_ERRnosupport },

    { NQ_ERR_NOWRITE,            HRD_ERRnowrite },
    { NQ_ERR_BADUNIT,            HRD_ERRbadunit },
    { NQ_ERR_NOTREADY,           HRD_ERRnotready },
    { NQ_ERR_BADCMD,             HRD_ERRbadcmd },
    { NQ_ERR_DATA,               HRD_ERRdata },
    { NQ_ERR_BADREQ,             HRD_ERRbadreq },
    { NQ_ERR_SEEK,               HRD_ERRseek },
    { NQ_ERR_BADMEDIA,           HRD_ERRbadmedia },
    { NQ_ERR_BADSECTOR,          HRD_ERRbadsector },
    { NQ_ERR_NOPAPER,            HRD_ERRnopaper },
    { NQ_ERR_WRITE,              HRD_ERRwrite },
    { NQ_ERR_READ,               HRD_ERRread },
    { NQ_ERR_GENERAL,            HRD_ERRgeneral },
    { NQ_ERR_BADSHARE,           HRD_ERRbadshare },
    { NQ_ERR_LOCK,               HRD_ERRlock },
    { NQ_ERR_WRONGDISK,          HRD_ERRwrongdisk },
    { NQ_ERR_FCBUNAVAIL,         HRD_ERRFCBUnavail },
    { NQ_ERR_SHAREBUFEXC,        HRD_ERRsharebufexc },
    { NQ_ERR_DISKFULL,           HRD_ERRdiskfull }
};

struct cifsNtErrorMap
{
    NQ_UINT32 nqError;          /* internal error */
    NQ_UINT32 status;           /* SMB status */
}
/* Mapping NQ internal errors to SMB errors.
	When one NQ error is mapped to more than one SMB error (NQ error appears twice or more)
	please make sure the "best" translation appears first in the table.
*/

static smbNtToSysErrorMap[] =
{
    { NQ_ERR_OK,              0},
    { NQ_ERR_OK,              SMB_STATUS_OK },
    { NQ_ERR_ERROR,           SMB_STATUS_UNSUCCESSFUL },
    { NQ_ERR_BADPARAM,        SMB_STATUS_INVALID_PARAMETER },
    { NQ_ERR_BADPARAM,        SMB_STATUS_CTL_FILE_NOT_SUPPORTED },
    { NQ_ERR_LOGONFAILURE,    SMB_STATUS_LOGON_FAILURE },
    { NQ_ERR_LOGONFAILURE,	  SMB_STATUS_LOGON_TYPE_NOT_GRANTED},
    { NQ_ERR_BADACCESS,       SMB_STATUS_ACCESS_DENIED },
    { NQ_ERR_BADACCESS,       SMB_STATUS_ACCOUNT_RESTRICTION },
    { NQ_ERR_BADFILE,         SMB_STATUS_OBJECT_NAME_NOT_FOUND },
    { NQ_ERR_BADFILE,         SMB_STATUS_NO_SUCH_FILE },
    { NQ_ERR_BADSHARE,        SMB_STATUS_BAD_NETWORK_NAME },
    { NQ_ERR_BADSHARE,        SMB_STATUS_SHARING_VIOLATION },
    { NQ_ERR_ALREADYEXISTS,   SMB_STATUS_OBJECT_NAME_COLLISION },
    { NQ_ERR_PATHNOTCOVERED,  SMB_STATUS_PATH_NOT_COVERED },
    { NQ_ERR_PATHNOTCOVERED,  SMB_STATUS_IO_REPARSE_TAG_NOT_HANDLED },
    { NQ_ERR_INVALIDHANDLE,   SMB_STATUS_INVALID_HANDLE },
    { NQ_ERR_NOACCESS,        SMB_STATUS_ACCESS_DENIED },
    { NQ_ERR_NOMEM,           SMB_STATUS_NO_MEMORY },
    { NQ_ERR_DISKFULL,        SMB_STATUS_DISK_FULL },
    { NQ_ERR_WRONGDISK,       SMB_STATUS_WRONG_VOLUME },
    { NQ_ERR_OBJEXISTS,       SMB_STATUS_OBJECT_NAME_COLLISION },
    { NQ_ERR_BADMEDIA,        SMB_STATUS_DISK_OPERATION_FAILED },
    { NQ_ERR_BADMEDIA,        SMB_STATUS_DEVICE_POWER_FAILURE },
    { NQ_ERR_BADMEDIA,        SMB_STATUS_DEVICE_OFF_LINE },
    { NQ_ERR_BADPATH,         SMB_STATUS_BAD_NETWORK_PATH },
    { NQ_ERR_BADPATH,         SMB_STATUS_OBJECT_PATH_NOT_FOUND },
    { NQ_ERR_BADPATH,         SMB_STATUS_FILE_IS_A_DIRECTORY },
    { NQ_ERR_BADREQ,          SMB_STATUS_INFO_LENGTH_MISMATCH },
    { NQ_ERR_NOTREADY,		  SMB_STATUS_DEVICE_NOT_READY },
    { NQ_ERR_NOTREADY,        SMB_STATUS_NO_MEDIA_IN_DEVICE },
    { NQ_ERR_BADSECTOR,       SMB_STATUS_NONEXISTENT_SECTOR },
    { NQ_ERR_MOREDATA,		  SMB_STATUS_MORE_PROCESSING_REQUIRED },
    { NQ_ERR_MOREDATA,        SMB_STATUS_BUFFER_OVERFLOW },
    { NQ_ERR_MOREDATA,		  SMB_STATUS_MORE_ENTRIES },
    { NQ_ERR_MOREDATA,        SMB_STATUS_BUFFER_TOO_SMALL },
    { NQ_ERR_NOFILES,         SMB_STATUS_NO_MORE_FILES },
    { NQ_ERR_INVALIDNAME,     SMB_STATUS_OBJECT_NAME_INVALID },
    { NQ_ERR_BADFUNC,         SMB_STATUS_NOT_IMPLEMENTED },
    { NQ_ERR_DATA,            SMB_STATUS_DATA_ERROR },
    { NQ_ERR_LOCK,			  SMB_STATUS_NOT_LOCKED },
    { NQ_ERR_LOCK,            SMB_STATUS_LOCK_NOT_GRANTED },
    { NQ_ERR_BADPW,           SMB_STATUS_WRONG_PASSWORD },
    { NQ_ERR_GENERAL,         SMB_STATUS_FILE_INVALID },
    { NQ_ERR_NOWRITE,         SMB_STATUS_MEDIA_WRITE_PROTECTED },
    { NQ_ERR_BADPIPE,         SMB_STATUS_INVALID_PIPE_STATE },
    { NQ_ERR_PIPEBUSY,        SMB_STATUS_PIPE_BUSY },
    { NQ_ERR_PIPEBUSY,        SMB_STATUS_PIPE_EMPTY},
    { NQ_ERR_PIPECLOSING,     SMB_STATUS_PIPE_CLOSING },
    { NQ_ERR_NOTCONNECTED,    SMB_STATUS_PIPE_DISCONNECTED },
    { NQ_ERR_NOSHARE,         SMB_STATUS_BAD_NETWORK_NAME },
    { NQ_ERR_DONTSUPPORTIPC,  SMB_STATUS_BAD_DEVICE_TYPE },
    { NQ_ERR_NOSUPPORT,       SMB_STATUS_NOT_SUPPORTED },
    { NQ_ERR_NOSUPPORT,       SMB_STATUS_UNMAPPABLE_CHARACTER },
    { NQ_ERR_DIFFDEVICE,      SMB_STATUS_NOT_SAME_DEVICE },
    { NQ_ERR_DIFFDEVICE,      SMB_STATUS_NO_SUCH_DEVICE },
    { NQ_ERR_NOFIDS,          SMB_STATUS_TOO_MANY_OPENED_FILES },
    { NQ_ERR_INVFID,          SMB_STATUS_ADDRESS_ALREADY_EXISTS },
    { NQ_ERR_BADDIRECTORY,    SMB_STATUS_NOT_A_DIRECTORY },
    { NQ_ERR_BADDIRECTORY,    SMB_STATUS_INVALID_INFO_CLASS },
    { NQ_ERR_ACCOUNTLOCKEDOUT,SMB_STATUS_ACCOUNT_LOCKED_OUT },
    { NQ_ERR_QEOF,            SMB_STATUS_END_OF_FILE },
    { NQ_ERR_USEREXISTS,      SMB_STATUS_USER_EXISTS },
    { NQ_ERR_USERNOTFOUND,	  SMB_STATUS_NO_TRUST_SAM_ACCOUNT },
    { NQ_ERR_USERNOTFOUND,    SMB_STATUS_NONE_MAPPED },
    { NQ_ERR_VOLUMEDISMOUNTED,SMB_STATUS_VOLUME_DISMOUNTED },
    { NQ_ERR_DIRNOTEMPTY,     SMB_STATUS_DIRECTORY_NOT_EMPTY },
    { NQ_ERR_NETWORKERROR,	  SMB_STATUS_UNEXPECTED_NETWORK_ERROR },
    { NQ_ERR_NETWORKERROR,    SMB_STATUS_DUPLICATE_NAME },
    { NQ_ERR_NETWORKERROR,    SMB_STATUS_NETWORK_NAME_DELETED },
    { NQ_ERR_NETWORKERROR,    SMB_STATUS_NETWORK_BUSY },   
    { NQ_ERR_NETWORKERROR,    SMB_STATUS_NETWORK_UNREACHABLE },
    { NQ_ERR_NETWORKERROR,    SMB_STATUS_HOST_UNREACHABLE },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_CONNECTION_DISCONNECTED },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_CONNECTION_REFUSED },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_CONNECTION_RESET },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_VIRTUAL_CIRCUIT_CLOSED },    
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_REMOTE_NOT_LISTENING },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_INVALID_NETWORK_RESPONSE },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_REQUEST_NOT_ACCEPTED },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_NETLOGON_NOT_STARTED },
    { NQ_ERR_BADCONNECTION,   SMB_STATUS_NO_SUCH_LOGON_SESSION },
	{ NQ_ERR_TRYAGAIN,        SMB_STATUS_USER_SESSION_DELETED },
	{ NQ_ERR_TRYAGAIN,        SMB_STATUS_FILE_CLOSED },
    { NQ_ERR_BADDFS,          SMB_STATUS_FS_DRIVER_REQUIRED },
    { NQ_ERR_BADDFS,          SMB_STATUS_DFS_UNAVAILABLE },
    { NQ_ERR_SHARINGPAUSED,   SMB_STATUS_SHARING_PAUSED },
    { NQ_ERR_IOTIMEOUT,       SMB_STATUS_IO_TIMEOUT },
    { NQ_ERR_NORESOURCE,      SMB_STATUS_INSUFFICIENT_RESOURCES }
};

/* -- API Functions */

NQ_UINT32 ccErrorsStatusToNq(NQ_UINT32 status, NQ_BOOL isNt)
{
    NQ_COUNT i;                 /* just a counter */
    NQ_COUNT mapSize;           /* its size */
    NQ_UINT32 nqErr;            /* internal (intermediate) error code */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "status:0x%8x isNt:%s", status, isNt ? "TRUE" : "FALSE");
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "status = %8lx, isNt == %d", status, isNt);*/

    if (isNt)
    {
        mapSize = sizeof(smbNtToSysErrorMap) / sizeof(smbNtToSysErrorMap[0]);
        for (i = 0; i < mapSize; i++)
        {
            if ((smbNtToSysErrorMap + i)->status == status)
            {
                nqErr = (smbNtToSysErrorMap + i)->nqError;
                goto Exit;
            }
        }
    }
    else
    {
        mapSize = sizeof(smbDosToSysErrorMap) / sizeof(smbDosToSysErrorMap[0]);
        for (i = 0; i < mapSize; i++)
        {
            if ((smbDosToSysErrorMap + i)->code == status
               )
            {
                nqErr = (smbDosToSysErrorMap + i)->nqError;
                goto Exit;
            }
        }
    }

    nqErr = NQ_ERR_GENERAL;     /* default */

Exit:
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NQ error code=%ld (0x%X)", nqErr, nqErr);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", nqErr);
    return nqErr;
}

NQ_UINT32 ccGetNTStatus(void)
{
    NQ_UINT32 result = SMB_STATUS_INVALID;
    CMThread *pThread = cmThreadGetCurrent();

    if (NULL == pThread)
        goto Exit;

    result = pThread->status;

Exit:
    return result;
}

NQ_UINT32 ccErrorToSmbStatus(NQ_UINT32 nqError)
{
    NQ_COUNT mapSize, i;                      /* error map size */
    NQ_UINT32 SMBStatus = SMB_STATUS_INVALID; /* SMB error code */		


    mapSize = sizeof(smbNtToSysErrorMap) / sizeof(smbNtToSysErrorMap[0]);
    for (i = 0; i < mapSize; ++i)
    {
        if ((smbNtToSysErrorMap + i)->nqError == nqError)
        {
            SMBStatus = (smbNtToSysErrorMap + i)->status;
            goto Exit;
        }        
    }
    
    if (IS_NQ_ERROR(nqError))
    {
        SMBStatus = SMB_STATUS_UNSUCCESSFUL;
        goto Exit;
    }

	/* the error code isn't NQ error code - no translation exists. */
    SMBStatus = SMB_STATUS_INVALID;

Exit:
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NQ error code=%ld (0x%X), SMB status=%d", nqError, nqError, SMBStatus);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result - SMB status: %d, (0x%X) ", SMBStatus, SMBStatus);
    return SMBStatus; 
}


