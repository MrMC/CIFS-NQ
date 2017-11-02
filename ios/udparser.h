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

#ifndef _UDPARSER_H_
#define _UDPARSER_H_

#define UD_PARSERBUFFERSIZE 512         /* size of the buffer to read from file */

typedef struct              /* working store for parsing */
{
    int file;                       /* file to read from */
    char buf[UD_PARSERBUFFERSIZE];  /* temporary buffer filled with a next chunk from the file */
    int idx;                        /* current position in the buffer */
    char unget;                     /* unget character or zero */
    unsigned long offset;           /* current offset in the parsed file */
} ParseContext;

int     /* prepare to parse: 1 on success, 0 on error */
parseInit(
    ParseContext* parser,
    const char* fileName
    );

void    /* stop parsing */
parseStop(
    ParseContext* parser
    );

void     /* read a portion from the file */
parseReadChunk(
    ParseContext* parser
    );

char     /* get one char from the file */
parseGet(
    ParseContext* parser
    );

void     /* return one char back to "file" */
parseUnget(
    ParseContext* parser,
    char backChar
    );

void     /* skips white spaces if any */
parseSkipSpaces(
    ParseContext* parser
    );

void     /* skips to EOL */
parseSkipLine(
    ParseContext* parser
    );

void     /* reads a name */
parseName(
    ParseContext* parser,
    char* value,
    int limit
    );

void     /* reads a value */
parseValue(
    ParseContext* parser,
    char* value,
    int limit,
    char delimiter
    );

int     /* check on EOF */
parseDelimiter(
    ParseContext* parser,
    char delimiter
    );

char     /* check on EOF */
parseAtFileEnd(
    ParseContext* parser
    );

int     /* check on EOL */
parseAtLineEnd(
    ParseContext* parser
    );

#endif /* _UDPARSER_H_ */
