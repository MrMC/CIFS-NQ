
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : DES encryption
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 29-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMFSDES_H_
#define _CMFSDES_H_

#include "cmapi.h"

/* encrypt 64-byte strings using DES algorithm */

void
cmCifsEncryptDES(
    NQ_BYTE* result,           /* the result */
    const NQ_BYTE* src,        /* to encrypt */
    const NQ_BYTE* key         /* encryption key */
    );

#endif  /* _CMFSDES_H_ */

