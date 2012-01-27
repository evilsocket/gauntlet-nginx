/*
 * This file is part of the Gauntlet security system.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * Gauntlet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Gauntlet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Gauntlet.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GAUNTLET_PARSER_H
# define GAUNTLET_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <math.h>

#define GT_PARSER_SUCCESS  0
#define GT_PARSER_ERROR    1
#define GT_MAX_STRING_SIZE 0xFF

#define GT_ZEROIZE( s ) memset( s, 0x00, GT_MAX_STRING_SIZE )

typedef unsigned char u_char;

typedef struct
{
  u_char scope[ GT_MAX_STRING_SIZE ];
  u_char filter[ GT_MAX_STRING_SIZE ];
  double score;
}
gt_filter_t;

typedef struct
{
  size_t       nfilters;
  gt_filter_t *filters;
}
gt_chain_t;

typedef struct
{
  u_char     name[ GT_MAX_STRING_SIZE ];
  u_char     author[ GT_MAX_STRING_SIZE ];
  double     threshold;
  gt_chain_t chain;
}
gt_rule_t;

typedef struct
{
  u_char       error[ GT_MAX_STRING_SIZE ];
  size_t       lineno;  
  u_char      *buffer;
  size_t       bsize;
  gt_filter_t *filter;
}
gt_parser_t;

void   gt_parser_init( gt_parser_t *parser );
size_t gt_parser_readfile( gt_parser_t *parser, FILE *fp );
size_t gt_parse_rule( gt_parser_t *parser, gt_rule_t *rule );
void   gt_rule_free( gt_rule_t *rule );
void   gt_parser_free( gt_parser_t *parser );

#endif
