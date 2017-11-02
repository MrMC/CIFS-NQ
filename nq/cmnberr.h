/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Definition of API error codes for NetBIOS
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMNBERR_H_
#define _CMNBERR_H_

/********************************************************************
 *      Error numbers
 ********************************************************************/

#define CM_NBERR_ILLEGALSOCKETSLOT          NQ_ERR_NBILLEGALSOCKETSLOT
#define CM_NBERR_NOTNETBIOSNAME             NQ_ERR_NBNOTNETBIOSNAME
#define CM_NBERR_TIMEOUT                    NQ_ERR_NBTIMEOUT
#define CM_NBERR_NEGATIVERESPONSE           NQ_ERR_NBNEGATIVERESPONSE
#define CM_NBERR_HOSTNAMENOTRESOLVED        NQ_ERR_NBHOSTNAMENOTRESOLVED
#define CM_NBERR_CANCELLISTENFAIL           NQ_ERR_NBCANCELLISTENFAIL
#define CN_NBERR_SOCKETOVERFLOW             NQ_ERR_NBSOCKETOVERFLOW
#define CM_NBERR_NOBINDBEFORELISTEN         NQ_ERR_NBNOBINDBEFORELISTEN
#define CM_NBERR_ILLEGALDATAGRAMSOURCE      NQ_ERR_NBILLEGALDATAGRAMSOURCE
#define CM_NBERR_ILLEGALDATAGRAMDESTINATION NQ_ERR_NBILLEGALDATAGRAMDESTINATION
#define CM_NBERR_INVALIDPARAMETER           NQ_ERR_NBINVALIDPARAMETER
#define CM_NBERR_INTERNALERROR              NQ_ERR_NBINTERNALERROR
#define CM_NBERR_ILLEGALDATAGRAMTYPE        NQ_ERR_NBILLEGALDATAGRAMTYPE
#define CM_NBERR_DDCOMMUNICATIONERROR       NQ_ERR_NBDDCOMMUNICATIONERROR
#define CM_NBERR_BUFFEROVERFLOW             NQ_ERR_NBBUFFEROVERFLOW
#define CM_NBERR_RELEASENAMEFAIL            NQ_ERR_NBRELEASENAMEFAIL

#endif  /* _CMNBERR_H_ */

