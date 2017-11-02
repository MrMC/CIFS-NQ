/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Error codes
 *--------------------------------------------------------------------
 * MODULE        : UD - user dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 10-Jul-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include <errno.h>

#include "udapi.h"

/*
    Static functions & data
    -----------------------
 */
/* error mapping array: first value is a system error code, second value is an
   SMB error code */

struct cifsErrorMap
{
    unsigned int sysError;      /* system error */
    unsigned long smbError;     /* SMB error */
}

/* The table(s) of system errors mapped to SMB erros. */

sysToSmbErrorMap[] =
{
    { ENOENT, DOS_ERRbadfile },
    { EBADF, DOS_ERRbadfid },
    { EACCES, DOS_ERRnoaccess },
    { ENOTEMPTY, DOS_ERRdirnotempty },
    { EEXIST, DOS_ERRfileexists },
    { EXDEV, DOS_ERRdiffdevice },
    { EMFILE, DOS_ERRnofids },
    { ENAMETOOLONG, DOS_ERRinvalidname },
    { ENOSPC, HRD_ERRdiskfull },
    { EROFS, DOS_ERRnoaccess },
    { EMLINK, DOS_ERRnofids },
    { EISDIR, DOS_ERRbadfile }
    /* Additional mappings go here */
    /* general format: */
    /* {system-error-code, 32-bit-smb-error-code }, */
};

/* error mapping array: first value is an NQ error code, second value is a system
   error code */

static struct nqErrorMap
{
    unsigned long nqError;     /* NQ error */
    unsigned int sysError;      /* system error */
}

/* The table(s) of NQ erros mapped on system errors.
   Lines commented out are designate NQ errors that are not mapped. Those codes are
   converted into module & code format. */

nqToSysErrorMap[] =
{
    /* Error mappings go here */
    /* general format: */
    /* {system-error-code, 32-bit-smb-error-code }, */
    { NQ_ERR_BADPARAM,        EINVAL },

    { NQ_ERR_BADFILE,         ENOENT },
    { NQ_ERR_BADPATH,         ENOENT },
    { NQ_ERR_NOFIDS,          EMFILE },
//    { NQ_ERR_BADFORMAT,       EMEDIUMTYPE },  comment by ryuu
    { NQ_ERR_BADDATA,         EIO },
    { NQ_ERR_DIFFDEVICE,      EXDEV },
    { NQ_ERR_NOFILES,         EMFILE },
    { NQ_ERR_FILEXISTS,       EEXIST },
    { NQ_ERR_BADDIRECTORY,    ENOTEMPTY },
    { NQ_ERR_INSUFFICIENTBUFFER, ENOBUFS },
    { NQ_ERR_INVALIDNAME,     ENAMETOOLONG },
    { NQ_ERR_ALREADYEXISTS,   EEXIST },
    { NQ_ERR_NOSUPPORT,       EPERM },
    { NQ_ERR_BADACCESS,       EPERM },
    { NQ_ERR_BADMEDIA,        ENODEV },
    { NQ_ERR_WRITE,           EPERM },
    { NQ_ERR_READ,            EROFS },
    { NQ_ERR_DISKFULL,        ENOSPC },
    { NQ_ERR_BADDRIVE,        ENXIO },
    { NQ_ERR_SEEK,            ESPIPE },
    { NQ_ERR_DIRNOTEMPTY,     ENOTEMPTY }
};

/*
 *====================================================================
 * PURPOSE: convert system error to SMB error
 *--------------------------------------------------------------------
 * PARAMS:  system error code
 *
 * RETURNS: SMB error or 0 to use the default conversion
 *
 * NOTES:
 *
 *====================================================================
 */

unsigned long
udGetSmbError(
    unsigned long sysErr
    )
{
    unsigned int i;    /* just an index */

    /* use system-dependent conversion table */

    for (i = 0; i < sizeof(sysToSmbErrorMap)/sizeof(struct cifsErrorMap); i++)
    {
        if (sysToSmbErrorMap[i].sysError == sysErr)
        {
            return sysToSmbErrorMap[i].smbError;
        }
    }

    return (unsigned long)SRV_ERRerror;
}

/*
 *====================================================================
 * PURPOSE: convert internal NQ error to system error
 *--------------------------------------------------------------------
 * PARAMS:  IN NT-format SMB error code
 *
 * RETURNS: system error or 0 to use the default conversion
 *
 * NOTES:
 *
 *====================================================================
 */

unsigned long
udNqToSystemError(
    unsigned long ntErr
    )
{
    unsigned int i;          /* just an index */

    /* use system-dependent conversion table */

    for (i = 0; i < sizeof(nqToSysErrorMap)/sizeof(nqToSysErrorMap[0]); i++)
    {
        if (nqToSysErrorMap[i].nqError == ntErr)
        {
            return nqToSysErrorMap[i].sysError;
        }
    }

    return ntErr == 0? 0 : (unsigned long) (-1);
}
