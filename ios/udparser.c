/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Configuration parsing - parsing primitives
 *--------------------------------------------------------------------
 * MODULE        : UD - user defined
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 6-Jun-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "syinclud.h"

#include "udparser.h"

/*
  This file implements parsing of an abstract configuration file.

  It is used for a sample implementation of UD functions when most parameters are
  supplied in configuration files. The functions in this file implement parsing primitives
  for building comprehensive parsers.

  Configuration file contains lines of the following types:

  1) line of comments has a "#" sign in the first meaninfull (not a whitespace) position

     # this is a comment
     # this is a comment either

  2) empty line contains whitespaces only and may be of a zero length too
  3) parameter line looks as follows:

     <name><delimiter><value>[<delimiter><value>]

  <delimiter> stands for any printable character
  <name> stands for any combination of alphanumeric characters and underscore
  <value> stands for any combunation of printable characters except the delimiter

  whitespaces are allowed between clauses
  parameter value may contain additional eqiation signs

 */

/*
   Static functions, definiitons and data
   --------------------------------------
 */

#ifndef EOF
#define EOF         char(-1)    /* end-of-file mark */
#endif

/* character classification */

#define isControlChar(_c)  \
    ((_c)<' ' && (_c)!='\t' && (_c)!='=')  /* determine control character */

#define isWhiteSpace(_c)  \
    ((_c)==' ' || (_c)=='\t')     /* determine whitespace character */

/*
    According to Microsoft characters not allowed in user name: \/"[]:|<>+=;,?*@
*/
#define isNameChar(_c)             \
    ((_c)=='.'  || \
      (_c)==' ' || (_c)=='!'    || \
     ((_c)>='^' && (_c)<='`')   || \
     ((_c)>='#' && (_c)<=')')   || \
     ((_c)>='0' && (_c)<='9')   || \
     ((_c)>='a' && (_c)<='z')   || \
     ((_c)>='A' && (_c)<='Z')  )   /* determine alphanumeric character */


/*
 *====================================================================
 * PURPOSE: Prepare for parsing
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *          IN configuration file name
 *
 * RETURNS: 1 on success, 0 on error
 *
 * NOTES:   Opens file and sets up the context
 *====================================================================
 */

int
parseInit(
    ParseContext* parser,
    const char* fileName
    )
{
    parser->idx = UD_PARSERBUFFERSIZE;
    parser->unget = (char)0;
    parser->offset = 0L;
    parser->file = open(fileName, O_RDONLY, 0777);

    return (parser->file != ERROR);
}

/*
 *====================================================================
 * PURPOSE: Stop parsing
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *
 * RETURNS: NONE
 *
 * NOTES:   Closes the file
 *====================================================================
 */

void
parseStop(
    ParseContext* parser
    )
{
    if (parser->file > 0) close(parser->file);
    parser->file = -1;
}

/*
 *====================================================================
 * PURPOSE: read a portion from the file if the buffer is empty
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *
 * RETURNS: 1 on success, 0 on error
 *
 * NOTES:   On EOF or on error "reads" an EOF mark
 *====================================================================
 */

void
parseReadChunk(
    ParseContext* parser
    )
{
    long res;

    if (parser->idx < UD_PARSERBUFFERSIZE)
        return;

    res = read(parser->file, parser->buf, UD_PARSERBUFFERSIZE);
    if (res == ERROR)
    {
        res = 0;    /* EOF */
        parseStop(parser);
    }

    parser->idx = 0;
    if (res < UD_PARSERBUFFERSIZE)
    {
        parser->buf[res] = (char) EOF;
        parseStop(parser);
    }

    parser->offset = (unsigned long)(parser->offset + (unsigned long)res);
    // comment by ryuu
//    lseek(parser->file, (__off_t)parser->offset, SEEK_SET);  /* ignore errors */

    return;
}

/*
 *====================================================================
 * PURPOSE: get one char from a file
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *
 * RETURNS: the character
 *
 * NOTES:   Tries to get the char from the buffer. Reads from the file if
 *          necessary
 *====================================================================
 */

char
parseGet(
    ParseContext* parser
    )
{
    char c;

    if (parser->unget != (char)0)   /* there is something to unget */
    {
        c = parser->unget;
        parser->unget= (char)0;
        return c;
    }

    parseReadChunk(parser);

    c = (char)(parseAtFileEnd(parser) ? EOF : parser->buf[parser->idx++]);

    return c;
}

/*
 *====================================================================
 * PURPOSE: return one char back to "stream"
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *          IN the character to return
 *
 * RETURNS: NONE
 *
 * NOTES:   there may be only one "unget"
 *====================================================================
 */

void
parseUnget(
    ParseContext* parser,
    char backChar
    )
{
    parser->unget = backChar;
}

/*
 *====================================================================
 * PURPOSE: skip whitespaces
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *
 * RETURNS: NONE
 *
 * NOTES:   any number of whitespaces (space or tab) will be skipped
 *          (if any)
 *====================================================================
 */

void
parseSkipSpaces(
    ParseContext* parser
    )
{
    char c;

    do
        c = parseGet(parser);
    while (isWhiteSpace(c));

    if (c!=(char)EOF)
        parseUnget(parser, c);
}

/*
 *====================================================================
 * PURPOSE: skip to EOL
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *
 * RETURNS: NONE
 *
 * NOTES:   Skips all characters until the end of the current line is
 *          reached
 *====================================================================
 */

void
parseSkipLine(
    ParseContext* parser
    )
{   char c;

    while ((c=parseGet(parser)) != (char)EOF)
    {
        if (isControlChar(c))
        {
            /* skip while control characters (if any) */

            while ((c=parseGet(parser)) != (char)EOF && isControlChar(c));
            parseUnget(parser, c);
            break;
        }
    }
}

/*
 *====================================================================
 * PURPOSE: read a name
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *          OUT buffer for a name
 *          IN this buffer length
 *
 * RETURNS: NONE
 *
 * NOTES:   Reads any combination of alphanumeric characters. Name may
 *          be truncated because of illegal character.
 *====================================================================
 */

void
parseName(
    ParseContext* parser,
    char* name,
    int limit
    )
{
    int i;
    char c;

    for (i=limit; i != 0; i--)
    {
        char c;

        c = parseGet(parser);

        if (!isNameChar(c))
        {
            parseUnget(parser, c);
            *name = (char)0;
            return;
        }

        *name++ = c;
    }

    /* name is too long - skip */

    *name = (char)0;

    while ((c=parseGet(parser))!=(char)EOF)
    {
        if (!isNameChar(c))
        {
            parseUnget(parser, c);
            return;
        }
    }

    return;
}

/*
 *====================================================================
 * PURPOSE: read a value
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *          OUT buffer for a value
 *          IN this buffer length
 *          IN expected delimiter
 *
 * RETURNS: NONE
 *
 * NOTES:   Reads any combination of printable characters untile either
 *          a delimiter or EOL or EOF is reached. Value may be truncated.
 *          Use value of (char)0 as a delimiter to read to the EOL
 *====================================================================
 */

void
parseValue(
    ParseContext* parser,
    char* name,
    int limit,
    char delimiter
    )
{
    int i;
    char c;

    for (i=limit; i != 0; i--)
    {
        char c;

        c = parseGet(parser);

        if (isControlChar(c) || c==delimiter)
        {
            parseUnget(parser, c);
            *name = (char)0;
            return;
        }

        *name++ = c;
    }

    /* value is too long - skip */

    *name = (char)0;

    while ((c=parseGet(parser))!=(char)EOF)
    {
        if (isControlChar(c) || c==delimiter)
        {
            parseUnget(parser, c);
            return;
        }
    }

    return;
}

/*
 *====================================================================
 * PURPOSE: check on a delimiter
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *          IN expected delimiter
 *
 * RETURNS: 1 - match , 0 - unexpected characters
 *
 * NOTES:   Checks whether the next clause is a delimiter possibly
 *          enclosed in whitespaces
 *====================================================================
 */

int
parseDelimiter(
    ParseContext* parser,
    char delimiter
    )
{
    char c;

    parseSkipSpaces(parser);

    if ((c=parseGet(parser)) == delimiter)
    {
        parseSkipSpaces(parser);
        return 1;
    }

    parseUnget(parser, c);
    return 0;
}

/*
 *====================================================================
 * PURPOSE: check whether we are at the EOF
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *
 * RETURNS: 1 - EOF , 0 - not yet
 *
 * NOTES:
 *====================================================================
 */

char
parseAtFileEnd(
    ParseContext* parser
    )
{
    parseReadChunk(parser);

    if (parser->buf[parser->idx] == (char)EOF)
    {
        close(parser->file);
        parser->file = -1;
        return 1;
    }
    else
        return 0;
}

/*
 *====================================================================
 * PURPOSE: check whether we are at the EOL
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT parsing context
 *
 * RETURNS: 1 - EOL , 0 - not yet
 *
 * NOTES:
 *====================================================================
 */

int
parseAtLineEnd(
    ParseContext* parser
    )
{
    parseReadChunk(parser);

    return (isControlChar(parser->buf[parser->idx]));
}
