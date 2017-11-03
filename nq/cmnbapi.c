
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Initialization of the NetBIOS routines
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 6-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#include "cmapi.h"

/*
  This file implements axulliary functions common for all modules using NetBIOS:

  1) Initialization
*/

/*
 *====================================================================
 * PURPOSE: Initiazlize the NetBIOS part of the library
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS:  NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   1) read configuration from the file
 *          2) initialize those NetBIOS components that require
 *             initialization
 *====================================================================
 */

NQ_STATUS
cmNetBiosInit(
    void
    )
{
    /* initialize components that require initialization */

    return cmNetBiosNameInit();
}

/*
 *====================================================================
 * PURPOSE: Close the NetBIOS part of the library
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   1) read configuration from the file
 *          2) initialize those NetBIOS components that require
 *             initialization
 *====================================================================
 */

void
cmNetBiosExit(
    void
    )
{
    /* initialize components that require initialization */

    cmNetBiosNameExit();
}
