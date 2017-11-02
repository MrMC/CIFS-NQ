
/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Error conversion
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 18-Jan-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cserrors.h"
#include "csdispat.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/*
 * Static data
 */

static const struct ErrorMap
{
    NQ_UINT32 dos;
    NQ_UINT32 nt;
}
dos2NtMap[] = {
    {0 , 0},
    {SRV_ERRerror,          SMB_STATUS_UNSUCCESSFUL},
    {DOS_ERRbadfunc,        SMB_STATUS_NOT_IMPLEMENTED},
    {DOS_ERRbaddirectory,   SMB_STATUS_INVALID_INFO_CLASS},
    {HRD_ERRbadreq,         SMB_STATUS_INFO_LENGTH_MISMATCH},
    {DOS_ERRbadfid,         SMB_STATUS_INVALID_HANDLE},
    {DOS_ERRbadformat,      SMB_STATUS_INVALID_PARAMETER},
    {HRD_ERRwrongdisk,      SMB_STATUS_WRONG_VOLUME},
    {HRD_ERRnotready,       SMB_STATUS_NO_MEDIA_IN_DEVICE},
    {HRD_ERRbadsector,      SMB_STATUS_NONEXISTENT_SECTOR},
    {DOS_ERRnomem,          SMB_STATUS_NO_MEMORY},
    {DOS_ERRnoaccess,       SMB_STATUS_ACCESS_DENIED},
    {DOS_ERRbadaccess,      SMB_STATUS_ACCESS_DENIED},
    {DOS_ERRmoredata,       SMB_STATUS_BUFFER_OVERFLOW},
    {DOS_ERRnofiles,        SMB_STATUS_NO_MORE_FILES},
    {DOS_ERRinvalidname,    SMB_STATUS_OBJECT_NAME_INVALID},
    {DOS_ERRbadfile,        SMB_STATUS_OBJECT_NAME_NOT_FOUND},
    {DOS_ERRalreadyexists,  SMB_STATUS_OBJECT_NAME_COLLISION},
    {DOS_ERRbadpath,        SMB_STATUS_OBJECT_PATH_NOT_FOUND},
    {HRD_ERRdata,           SMB_STATUS_DATA_ERROR},
    {DOS_ERRbadshare,       SMB_STATUS_SHARING_VIOLATION},
    {DOS_ERRlock,           SMB_STATUS_LOCK_NOT_GRANTED},
    {HRD_ERRlock,           SMB_STATUS_NOT_LOCKED},
    {SRV_ERRbadpw,          SMB_STATUS_WRONG_PASSWORD},
    {HRD_ERRdiskfull,       SMB_STATUS_DISK_FULL},
    {HRD_ERRgeneral,        SMB_STATUS_FILE_INVALID},
    {HRD_ERRbadmedia,       SMB_STATUS_DEVICE_POWER_FAILURE},
    {HRD_ERRnowrite,        SMB_STATUS_MEDIA_WRITE_PROTECTED},
    {HRD_ERRnotready,       SMB_STATUS_DEVICE_NOT_READY},
    {DOS_ERRbadpipe,        SMB_STATUS_INVALID_PIPE_STATE},
    {DOS_ERRpipebusy,       SMB_STATUS_PIPE_BUSY},
    {DOS_ERRnotconnected,   SMB_STATUS_PIPE_DISCONNECTED},
    {DOS_ERRpipeclosing,    SMB_STATUS_PIPE_CLOSING},
    {(NQ_UINT32)SRV_ERRnosupport,      SMB_STATUS_NOT_SUPPORTED},
    {DOS_ERRdontsupportipc, SMB_STATUS_BAD_DEVICE_TYPE},
    {DOS_ERRnoshare,        SMB_STATUS_BAD_NETWORK_NAME},
    {DOS_ERRdiffdevice,     SMB_STATUS_NOT_SAME_DEVICE},
    {DOS_ERRdirnotempty,    SMB_STATUS_DIRECTORY_NOT_EMPTY},
    {DOS_ERRbaddirectory,   SMB_STATUS_NOT_A_DIRECTORY},
    {DOS_ERRnofids,         SMB_STATUS_TOO_MANY_OPENED_FILES},
    {SRV_ERRinvfid,         SMB_STATUS_ADDRESS_ALREADY_EXISTS},
};

/*====================================================================
 * PURPOSE: return appropriate error code
 *--------------------------------------------------------------------
 * PARAMS:  IN NT status
 *          IN DOS error code
 *
 * RETURNS: code to return
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csErrorReturn(
    NQ_UINT32 nt,
    NQ_UINT32 dos
    )   
{
    NQ_BOOL isNt;

    isNt = 0 == dos? TRUE: (0 == nt? FALSE : csDispatchIsNtError());
    csDispatchSetNtError(isNt);
    return isNt? nt : dos;
}

/*====================================================================
 * PURPOSE: obtain last system error converted to SMB error
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: code to return
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csErrorGetLast(
    void
    )
{
    NQ_UINT32 dos = syGetLastSmbError() != 0 ? syGetLastSmbError() : SRV_ERRerror;    /* projectlevel status - always dos */
    
    if (csDispatchIsNtError())
    {
        NQ_UINT i;   /* just a counter */

        for (i = 0; i < sizeof(dos2NtMap)/sizeof(dos2NtMap[0]); i++)
        {
            if (dos2NtMap[i].dos == dos)
                return dos2NtMap[i].nt;
        }
        return SMB_STATUS_INVALID;
    }
    else
        return dos;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

