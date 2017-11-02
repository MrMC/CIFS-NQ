/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client Initialization
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 3-Jul-2001
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccmount.h"
#include "ccserver.h"
#include "ccshare.h"
#include "ccfile.h"
#include "ccsearch.h"
#include "ccdfscache.h"
#include "ccdfs.h"
#include "ccutils.h"
#include "cctransport.h"
#include "ccconfig.h"
#include "cccifs.h"
#include "ccwrite.h"
#include "ccread.h" 
#include "ccdcerpc.h"
#include "ccsdescr.h"
#include "ccsrvsvc.h"
#include "ccsmb10.h"
#include "ccsmb20.h"
#include "ccsecure.h"
#include "nqapi.h"
#include "nsapi.h"
#include "ldapi.h"
#include "ccnetwrk.h"
#ifdef UD_CC_INCLUDEOLDBROWSERAPI
#include "ccbrowse.h"
#endif /* UD_CC_INCLUDEOLDBROWSERAPI */

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* static data */

static NQ_BOOL sCcIsInitialized = FALSE;

/*
 *====================================================================
 * PURPOSE: client module initialization
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to handle error notification handler
 *
 * RETURNS: TRUE if succeded, FALSE otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
ccInit(
    void (*fsdNotify)(NQ_INT eventId, NQ_ULONG param)
    )
{
    TRCB();

    if (!sCcIsInitialized)
    {
        ccConfigInit();

        /* new modules */
        if (NQ_SUCCESS != nsInit(TRUE)
        	|| !ccUtilsStart() 
            || !ccTransportStart() 
            || !ccMountStart()
        	|| !ccServerStart() 
            || !ccUserStart() 
            || !ccShareStart() 
            || !ccCifsStart()
        	|| !ccFileStart() 
            || !ccDfsCacheStart()
            || !ccDfsStart() 
            || !ccSearchStart()
        	|| !ccWriteStart() 
            || !ccReadStart() 
            || !ccDcerpcStart() 
            || !ccSdescrStart()
        	|| !ccSrvsvcStart() 
            || !ccSmb10Start() 
#ifdef UD_NQ_INCLUDESMB2
            || !ccSmb20Start() 
#endif
            || !ccSecureStart()
#ifdef UD_CC_INCLUDEOLDBROWSERAPI
            || !ccBrowseStart()
#endif /* UD_CC_INCLUDEOLDBROWSERAPI */
            || !ccNetworkStart()
        	)
        {
        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        	return FALSE;
        }
        
#ifdef UD_CC_INCLUDELDAP
        ldStart();
#endif
        sCcIsInitialized = TRUE;
    }

    TRCE();
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: client module shutdown
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ccShutdown(
    void
    )
{
    TRCB();

    if (sCcIsInitialized)
    {
        /* new modules */
        ccSearchShutdown();
        ccMountShutdown();
        ccServerShutdown();
        ccUserShutdown();
        ccShareShutdown();
        ccCifsShutdown();
        ccUtilsShutdown();
        ccTransportShutdown();
        ccFileShutdown();
        ccDfsShutdown();
        ccDfsCacheShutdown();
#ifdef UD_CC_INCLUDEOLDBROWSERAPI
        ccBrowseShutdown();
#endif /* UD_CC_INCLUDEOLDBROWSERAPI */
        ccNetworkShutdown();
        ccWriteShutdown();
        ccReadShutdown();
        ccDcerpcShutdown();
        ccSdescrShutdown();
        ccSrvsvcShutdown();
        ccSmb10Shutdown();
#ifdef UD_NQ_INCLUDESMB2
        ccSmb20Shutdown();
#endif
        ccSecureShutdown();
        ccConfigShutdown();

        nsExit(TRUE);
        sCcIsInitialized = FALSE;
    }

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: check if the client module initialized
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if initialized, FALSE otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL ccIsInitialized(void)
{
    return sCcIsInitialized;
}

/*
 *====================================================================
 * PURPOSE: dump client module data tables
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ccDump(
    void
    )
{
#if SY_DEBUGMODE
    if (sCcIsInitialized)
    {
        ccMountDump();
    }
#endif /* SY_DEBUGMODE */
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
