/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Initialization
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 25-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmtrace.h"
#include "cmfinddc.h"
#include "amspnego.h"

/*
  CM consists of two components: NetBIOS library and CIFS library. We initialize both
  of them.
 */

/*
 *====================================================================
 * PURPOSE: Initialize the library
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

NQ_STATUS
cmInit(
    void
    )
{
    
    if (sizeof(NQ_UINT32) != 4)
    {
        printf("Type 'long' is not 4 bytes on the target platform. Define SY_INT32 in SYCOMPIL.H\n");
        return NQ_FAIL;
    }

    if (NQ_FAIL == cmNetBiosInit())
    {
        return NQ_FAIL;
    }
        
    if (NQ_FAIL == cmCifsInit())
    {
        cmNetBiosExit();
        return NQ_FAIL;
    }

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)
    if (NQ_FAIL == cmSdInit())
    {
        cmNetBiosExit();
        cmCifsExit();      
        return NQ_FAIL;
    }    
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */

    if (NQ_FAIL == cmFindDCInit())
    {
        cmNetBiosExit();
        cmCifsExit();
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)      
        cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */       
        return NQ_FAIL;       
    }

    /* new modules */
    if (!cmMemoryStart(0))
    {
        cmNetBiosExit();
        cmCifsExit();
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)      
        cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
        cmFindDCInit();
        return NQ_FAIL;       
    }
    if (!cmSelfipStart())
    {
        cmNetBiosExit();
        cmCifsExit();   
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)      
        cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
        cmFindDCInit();
        cmMemoryShutdown();
        return NQ_FAIL;       
    }
    if (!cmResolverStart())
    {
        cmNetBiosExit();
        cmCifsExit();
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)      
        cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
        cmFindDCInit();
        cmMemoryShutdown();
        cmSelfipShutdown();
        return NQ_FAIL;       
    }

    if (!cmThreadStart())
    {
        cmNetBiosExit();
        cmCifsExit();
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)      
        cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
        cmFindDCInit();
        cmMemoryShutdown();
        cmSelfipShutdown();
        cmResolverShutdown();
        return NQ_FAIL;       
    }

	
#ifdef UD_NQ_INCLUDETRACE
    cmTraceInit();
#endif    

    if (!amSpnegoStart())
    {
        cmNetBiosExit();
        cmCifsExit();
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)      
        cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
        cmFindDCInit();
        cmMemoryShutdown();
        cmSelfipShutdown();
        cmResolverShutdown();
        cmThreadShutdown();
        return NQ_FAIL;       
    }
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Stop the library
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

void
cmExit(
    void
    )
{    
    cmNetBiosExit();
    cmCifsExit();
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)
    cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
    cmFindDCExit();
    /* new modules */
    cmResolverShutdown();
#ifdef UD_NQ_INCLUDETRACE
    cmTraceFinish();
#endif    
    cmThreadShutdown();
    cmSelfipShutdown();
    amSpnegoShutdown();
    cmMemoryShutdown();
}
