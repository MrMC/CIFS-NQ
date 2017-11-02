/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Trace common definitions
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 08-Dec-2008
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMTRACE_H_
#define _CMTRACE_H_

#include "nqapi.h"
#include "syopsyst.h"
#include "sytrace.h"
  

#define CM_TRC_INCLUDE_ERRORS             /* define this parameter to include TRCERR and LOGERR traces */
#define CM_TRC_INCLUDE_CALLS              /* define this parameter to include TRCB, TRCE and LOGFB , LOGFE traces */
#define CM_TRC_INCLUDE_MESSAGES           /* define this parameter to include TRC, TRCxP and LOGMSG traces */
#define CM_TRC_INCLUDE_DUMPS              /* define this parameter to include TRCDUMP traces */
#define CM_TRC_INCLUDE_TASKS              /* define this parameter to include LOGSTART and LOGSTOP traces */

#ifdef SY_TRC_DEBUG_LEVEL
#define CM_TRC_DEBUG_LEVEL          SY_TRC_DEBUG_LEVEL   /* default traces level threshold */
#else /* SY_TRC_DEBUG_LEVEL */
#define CM_TRC_DEBUG_LEVEL          500   /* default traces level threshold */
#endif /* SY_TRC_DEBUG_LEVEL */

#define CM_TRC_LEVEL_ASSERT         5     /* default level for LOGASSERT    */

/* levels for TRCERR: */
#define CM_TRC_LEVEL_LOW_ERROR		1001  /* low importance errors such as timeout in expected places*/
#define CM_TRC_LEVEL_ERROR          10    /* error   */
#define CM_TRC_LEVEL_WARNING        100   /* warning */

/* levels for LOGMSG, TRC, TRC1P, TRC2P, TRC3P: */
#define CM_TRC_LEVEL_MESS_ALWAYS    10    /* very important messages */
#define CM_TRC_LEVEL_MESS_NORMAL    200   /* intermediate messages   */
#define CM_TRC_LEVEL_MESS_SOME      700   /* less important messages */

/* levels for LOGFB, LOGFE, TRCB, TRCE: */
#define CM_TRC_LEVEL_FUNC_PROTOCOL  10    /* protocol or API functions */
#define CM_TRC_LEVEL_FUNC_TOOL      100   /* auxiliary functions       */
#define CM_TRC_LEVEL_FUNC_COMMON    1000  /* very common functions     */

#define CM_TRC_LEVEL_MEMORY			CM_TRC_LEVEL_ERROR          /* memory dump traces, to see only memory traces 
                                                                   define CM_TRC_DEBUG_LEVEL = CM_TRC_LEVEL_MEMORY */
#define CM_TRC_LEVEL_CMLIST         (CM_TRC_DEBUG_LEVEL + 1)    /* cmlist traces, not reported by default */


void cmTraceMessage(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *format, ...);
void cmTraceError(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *format, ...);
void cmTraceFuncEnter(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level);
void cmTraceFuncLeave(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level);
void cmTraceDump(const NQ_CHAR *file, const NQ_CHAR *function, NQ_UINT line, NQ_UINT level, const NQ_CHAR *str, const void *addr, NQ_UINT nBytes);
void cmTraceInit(void);
void cmTraceFinish(void);

#ifdef UD_NQ_INCLUDETRACE

#define LOGASSERT(_level, expr)      LOGERR(_level, "Assertion violation: " #expr); assert(expr);

#ifdef CM_TRC_INCLUDE_MESSAGES
#ifdef SY_C99_MACRO
#define LOGMSG(_level, _fmt,...)     cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, _level, _fmt, __VA_ARGS__)
#define TRC(_fmt,...)                cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, _fmt, __VA_ARGS__)
#define TRC1P(_fmt,...)              cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, _fmt, __VA_ARGS__)
#define TRC2P(_fmt,...)              cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, _fmt, __VA_ARGS__)
#define TRC3P(_fmt,...)              cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, _fmt, __VA_ARGS__)
#else 
#define LOGMSG(_level, _fmt...)      cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, _level, ##_fmt)
#define TRC(_fmt...)                 cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, ##_fmt)
#define TRC1P(_fmt...)               cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, ##_fmt)
#define TRC2P(_fmt...)               cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, ##_fmt)
#define TRC3P(_fmt...)               cmTraceMessage(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, ##_fmt)
#endif /* SY_C99_MACRO */
#else
#ifdef SY_C99_MACRO
#define LOGMSG(_level, _fmt,...)         
#define TRC(f,...)
#define TRC1P(f,...)            
#define TRC2P(f,...)        
#define TRC3P(f,...)  
#else
#define LOGMSG(_level, _fmt...)         
#define TRC(f...)
#define TRC1P(f...)            
#define TRC2P(f...)        
#define TRC3P(f...)  
#endif /* SY_C99_MACRO */             
#endif /* CM_TRC_INCLUDE_MESSAGES */
 
#ifdef CM_TRC_INCLUDE_ERRORS
#ifdef SY_C99_MACRO
#define LOGERR(_level, _fmt,...)     cmTraceError(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, _level, _fmt, __VA_ARGS__)
#define TRCERR(_fmt,...)             cmTraceError(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_ERROR, _fmt, __VA_ARGS__)
#else
#define LOGERR(_level, _fmt...)      cmTraceError(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, _level, ##_fmt)
#define TRCERR(_fmt...)              cmTraceError(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_ERROR, ##_fmt)
#endif /* SY_C99_MACRO */
#else
#ifdef SY_C99_MACRO
#define LOGERR(_level, _fmt,...)
#define TRCERR(f,...) 
#else
#define LOGERR(_level, _fmt...)
#define TRCERR(f...) 
#endif /* SY_C99_MACRO */
#endif /* CM_TRC_INCLUDE_ERRORS */

#ifdef CM_TRC_INCLUDE_CALLS
#define TRCB()                       cmTraceFuncEnter(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_FUNC_TOOL)
#define TRCE()                       cmTraceFuncLeave(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_FUNC_TOOL)
#define LOGFB(_level)                cmTraceFuncEnter(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, _level)
#define LOGFE(_level)                cmTraceFuncLeave(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, _level)
#else 
#define TRCB()                    
#define TRCE()
#define LOGFB(_level)                
#define LOGFE(_level)                
#endif /* CM_TRC_INCLUDE_CALLS */

#ifdef CM_TRC_INCLUDE_DUMPS
#define TRCDUMP(_str, _addr, _len)   cmTraceDump(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, CM_TRC_LEVEL_MESS_NORMAL, _str, _addr, _len)
#else 
#define TRCDUMP(_str, _addr, _len)
#endif /* CM_TRC_INCLUDE_DUMPS */

#ifdef CM_TRC_INCLUDE_TASKS       
#define LOGSTART(_name)              cmTraceStart(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, 0, _name)           
#define LOGSTOP(_name)               cmTraceStop(SY_LOG_FILE, SY_LOG_FUNCTION, SY_LOG_LINE, 0, _name)
#else 
#define LOGSTART(_name)                      
#define LOGSTOP(_name)            
#endif /* CM_TRC_INCLUDE_TASKS */


#else  /* #if UD_NQ_INCLUDETRACE */
#define LOGASSERT(_level, expr)
#define TRCB()                    
#define TRCE()
#define LOGFB(_level)                
#define LOGFE(_level)    
#define TRCDUMP(_str, _addr, _len)
#define LOGSTART(_name)                      
#define LOGSTOP(_name) 
#ifdef SY_C99_MACRO
#define LOGMSG(_level, _fmt,...)
#define TRC(f,...)
#define TRC1P(f,...)            
#define TRC2P(f,...)         
#define TRC3P(f,...)    
#define LOGERR(_level, _fmt,...)
#define TRCERR(f,...)      
#else
#define LOGMSG(_level, _fmt...)
#define TRC(f...)
#define TRC1P(f...)            
#define TRC2P(f...)         
#define TRC3P(f...)    
#define LOGERR(_level, _fmt...)
#define TRCERR(f...)      
#endif /* SY_C99_MACRO */
#endif /* UD_NQ_INCLUDETRACE */


#endif /* #ifndef _CMTRACE_H_ */
