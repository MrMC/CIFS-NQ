/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Generators of the most common NetBIOS packets
 *--------------------------------------------------------------------
 * MODULE        : CM Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmnbfram.h"

/*
  This file implements functions for generating the most common NetBIOS frames
  used by more then one module.
 */

/*
    Static data
    -----------
 */

static NQ_UINT16 nextTranId = 0;

/*
 *====================================================================
 * PURPOSE: Obtain next transaction ID
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Next transaction ID
 *
 * NOTES:   Tran ID is the same "running" number for all modules. It is not
 *          thread-safe which fact may cause (very rarely) the same Tran ID in two
 *          messages. This would not do any harm, however
 *====================================================================
 */

NQ_UINT16
cmNetBiosGetNextTranId(
    void
    )
{
    return nextTranId++;
}

/*
 *====================================================================
 * PURPOSE: Add necessary datagram flags
 *--------------------------------------------------------------------
 * PARAMS:  IN Already set flags
 *
 * RETURNS: All flag
 *
 * NOTES:   this function takes node flags and adds those flags that are
 *          the same for all modules (node type meanwhile)
 *====================================================================
 */

NQ_BYTE
cmNetBiosSetDatagramFlags(
    NQ_BYTE flags
    )
{
    TRCB();

    /* we are adding the node type */

    TRC1P("node type: 0x%x", cmNetBiosGetNodeType());

    switch (cmNetBiosGetNodeType())
    {
    case CM_NB_NAMEFLAGS_ONT_B:
        flags |= CM_NB_DATAGRAM_BNODE;
        break;
    case CM_NB_NAMEFLAGS_ONT_P:
        flags |= CM_NB_DATAGRAM_PNODE;
        break;
    case CM_NB_NAMEFLAGS_ONT_M:
        flags |= CM_NB_DATAGRAM_MNODE;
        break;
    default:
        TRCERR("Illegal node type");
        break;
    }

    TRCE();
    return flags;
}
