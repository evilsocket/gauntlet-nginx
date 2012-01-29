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
#ifndef GAUNTLET_RULE_PARSER_H
# define GAUNTLET_RULE_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <math.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define GT_PARSER_SUCCESS  0
#define GT_PARSER_ERROR    1
#define GT_MAX_STRING_SIZE 0xFF

#define GT_ZEROIZE( s ) ngx_memset( s, 0x00, GT_MAX_STRING_SIZE )

typedef ngx_array_t gt_ruleset_t;
typedef ngx_array_t gt_chain_t;

typedef struct
{
  u_char              scope[ GT_MAX_STRING_SIZE ];
  u_char              expression[ GT_MAX_STRING_SIZE ];
  ngx_regex_compile_t compiled;
  double              score;
}
gt_filter_t;

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
  // NGINX memory pool
  ngx_pool_t  *pool;
  // Parser last error
  u_char       error[ GT_MAX_STRING_SIZE ];
  // Current parser line number
  size_t       lineno;  
  // File buffer and buffer size
  u_char      *buffer;
  size_t       bsize;
  // Current rule being parsed
  gt_rule_t   *rule;
  // Current filter being parsed
  gt_filter_t *filter;
}
gt_parser_t;



void   gt_parser_init( gt_parser_t *parser, ngx_pool_t *pool );
size_t gt_parser_readfile( gt_parser_t *parser, ngx_fd_t fd );
size_t gt_parse_ruleset( gt_parser_t *parser, gt_ruleset_t *ruleset );
void   gt_rule_free( gt_rule_t *rule );
void   gt_parser_free( gt_parser_t *parser );

// For debugging purpose
void   gt_print_ruleset( gt_ruleset_t *ruleset );

#endif
