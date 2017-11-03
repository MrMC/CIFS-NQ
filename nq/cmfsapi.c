
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Initialization of the common CIFS routines
 *--------------------------------------------------------------------
 * MODULE        : CM - common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"

/*
  This file implememts those CIFS functions that are mandatory for other CIFS
  components:

  - initialization
  - release resources
 */

/*
 *====================================================================
 * PURPOSE: Initialize common routines
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *====================================================================
 */

NQ_STATUS
cmCifsInit(
    void
    )
{
    return cmCifsUtilsInit();
}

/*
 *====================================================================
 * PURPOSE: release common routines
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *====================================================================
 */

void
cmCifsExit(
    void
    )
{
    cmCifsUtilsExit();
}
