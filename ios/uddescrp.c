/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Access to file Security Descriptors
 *--------------------------------------------------------------------
 * MODULE        :
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 31-Jul-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "udapi.h"

/*
 *====================================================================
 * PURPOSE: Query user-defined security descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN file descriptor
 *          IN descriptor to get
 *          OUT buffer for the descriptor
 *
 * RETURNS: Descriptor lengths or -1 on error
 *
 * NOTES:   This implementation is a placeholder signaling that there
 *          are no security descriptors yet
 *====================================================================
 */

NQ_INT
udGetSecurityDescriptor(
    NQ_INT file,
    NQ_UINT32 information,
    void* buffer
    )
{
    return -1;
}

/*
 *====================================================================
 * PURPOSE: Write user-defined security descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN file descriptor
 *          IN descriptor to get
 *          IN the descriptor
 *          In descriptor length
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   This implementation is a placeholder signaling that there
 *          are no security descriptors yet
 *====================================================================
 */

NQ_STATUS
udSetSecurityDescriptor(
    NQ_INT file,
    NQ_UINT32 information,
    const void* buffer,
    NQ_UINT32 len
    )
{
    return -1;
}
