
#line 1 "src/g-rule-parser.rl"
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
#include "g-rule-parser.h"

#define GT_PARSER_FILL_STRING( s ) if( !( p = gt_parse_string( parser, p, pe, &s ) ) ) \
                                     return GT_PARSER_ERROR

#define GT_PARSER_FILL_REAL( r )   if( !( p = gt_parse_real( parser, p, pe, &r ) ) ) \
                                     return GT_PARSER_ERROR


#line 31 "src/g-rule-parser.c"
static const char _gt_rule_parser_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3, 1, 4, 1, 5, 1, 6, 1, 
	7, 1, 8, 2, 1, 0, 2, 5, 
	0
};

static const unsigned char _gt_rule_parser_key_offsets[] = {
	0, 0, 5, 13, 21, 22, 23, 24, 
	25, 26, 31, 36, 38, 40, 46, 46, 
	47, 48, 49, 50, 55, 60, 65, 71, 
	77, 78, 79, 80, 81, 82, 83, 84, 
	85, 86, 91, 96, 98, 100, 106, 112, 
	112, 113, 114, 116, 117, 122, 127, 129, 
	130, 135, 143, 145, 154, 156, 164, 165, 
	166, 167, 172, 177, 179, 180, 181, 182, 
	183, 184, 185, 186, 187, 192, 200, 202, 
	211, 213, 221
};

static const char _gt_rule_parser_trans_keys[] = {
	13, 32, 123, 9, 10, 13, 32, 97, 
	99, 110, 116, 9, 10, 13, 32, 97, 
	99, 110, 116, 9, 10, 117, 116, 104, 
	111, 114, 13, 32, 58, 9, 10, 13, 
	32, 34, 9, 10, 34, 92, 34, 92, 
	13, 32, 44, 125, 9, 10, 104, 97, 
	105, 110, 13, 32, 58, 9, 10, 13, 
	32, 91, 9, 10, 13, 32, 123, 9, 
	10, 13, 32, 101, 115, 9, 10, 13, 
	32, 101, 115, 9, 10, 120, 112, 114, 
	101, 115, 115, 105, 111, 110, 13, 32, 
	58, 9, 10, 13, 32, 34, 9, 10, 
	34, 92, 34, 92, 13, 32, 44, 125, 
	9, 10, 13, 32, 44, 93, 9, 10, 
	99, 111, 112, 114, 101, 13, 32, 58, 
	9, 10, 13, 32, 34, 9, 10, 34, 
	92, 101, 13, 32, 58, 9, 10, 13, 
	32, 43, 45, 9, 10, 48, 57, 48, 
	57, 13, 32, 44, 46, 125, 9, 10, 
	48, 57, 48, 57, 13, 32, 44, 125, 
	9, 10, 48, 57, 97, 109, 101, 13, 
	32, 58, 9, 10, 13, 32, 34, 9, 
	10, 34, 92, 104, 114, 101, 115, 104, 
	111, 108, 100, 13, 32, 58, 9, 10, 
	13, 32, 43, 45, 9, 10, 48, 57, 
	48, 57, 13, 32, 44, 46, 125, 9, 
	10, 48, 57, 48, 57, 13, 32, 44, 
	125, 9, 10, 48, 57, 13, 32, 44, 
	9, 10, 0
};

static const char _gt_rule_parser_single_lengths[] = {
	0, 3, 6, 6, 1, 1, 1, 1, 
	1, 3, 3, 2, 2, 4, 0, 1, 
	1, 1, 1, 3, 3, 3, 4, 4, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 3, 3, 2, 2, 4, 4, 0, 
	1, 1, 2, 1, 3, 3, 2, 1, 
	3, 4, 0, 5, 0, 4, 1, 1, 
	1, 3, 3, 2, 1, 1, 1, 1, 
	1, 1, 1, 1, 3, 4, 0, 5, 
	0, 4, 3
};

static const char _gt_rule_parser_range_lengths[] = {
	0, 1, 1, 1, 0, 0, 0, 0, 
	0, 1, 1, 0, 0, 1, 0, 0, 
	0, 0, 0, 1, 1, 1, 1, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 1, 1, 0, 0, 1, 1, 0, 
	0, 0, 0, 0, 1, 1, 0, 0, 
	1, 2, 1, 2, 1, 2, 0, 0, 
	0, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 1, 2, 1, 2, 
	1, 2, 1
};

static const short _gt_rule_parser_index_offsets[] = {
	0, 0, 5, 13, 21, 23, 25, 27, 
	29, 31, 36, 41, 44, 47, 53, 54, 
	56, 58, 60, 62, 67, 72, 77, 83, 
	89, 91, 93, 95, 97, 99, 101, 103, 
	105, 107, 112, 117, 120, 123, 129, 135, 
	136, 138, 140, 143, 145, 150, 155, 158, 
	160, 165, 172, 174, 182, 184, 191, 193, 
	195, 197, 202, 207, 210, 212, 214, 216, 
	218, 220, 222, 224, 226, 231, 238, 240, 
	248, 250, 257
};

static const char _gt_rule_parser_indicies[] = {
	0, 0, 2, 0, 1, 3, 3, 4, 
	5, 6, 7, 3, 1, 8, 8, 9, 
	10, 11, 12, 8, 1, 13, 1, 14, 
	1, 15, 1, 16, 1, 17, 1, 18, 
	18, 19, 18, 1, 20, 20, 21, 20, 
	1, 23, 24, 22, 26, 27, 25, 28, 
	28, 29, 30, 28, 1, 25, 31, 1, 
	32, 1, 33, 1, 34, 1, 35, 35, 
	36, 35, 1, 37, 37, 38, 37, 1, 
	39, 39, 40, 39, 1, 41, 41, 42, 
	43, 41, 1, 44, 44, 45, 46, 44, 
	1, 47, 1, 48, 1, 49, 1, 50, 
	1, 51, 1, 52, 1, 53, 1, 54, 
	1, 55, 1, 56, 56, 57, 56, 1, 
	58, 58, 59, 58, 1, 61, 62, 60, 
	64, 65, 63, 66, 66, 67, 68, 66, 
	1, 69, 69, 38, 26, 69, 1, 63, 
	70, 1, 71, 1, 72, 73, 1, 74, 
	1, 75, 75, 76, 75, 1, 77, 77, 
	78, 77, 1, 80, 81, 79, 82, 1, 
	83, 83, 84, 83, 1, 85, 85, 86, 
	86, 85, 87, 1, 88, 1, 66, 66, 
	67, 89, 68, 66, 88, 1, 90, 1, 
	66, 66, 67, 68, 66, 90, 1, 91, 
	1, 92, 1, 93, 1, 94, 94, 95, 
	94, 1, 96, 96, 97, 96, 1, 99, 
	100, 98, 101, 1, 102, 1, 103, 1, 
	104, 1, 105, 1, 106, 1, 107, 1, 
	108, 1, 109, 109, 110, 109, 1, 111, 
	111, 112, 112, 111, 113, 1, 114, 1, 
	28, 28, 29, 115, 30, 28, 114, 1, 
	116, 1, 28, 28, 29, 30, 28, 116, 
	1, 117, 117, 118, 117, 1, 0
};

static const char _gt_rule_parser_trans_targs[] = {
	1, 0, 2, 3, 4, 15, 54, 60, 
	3, 4, 15, 54, 60, 5, 6, 7, 
	8, 9, 9, 10, 10, 11, 12, 13, 
	14, 12, 13, 14, 13, 3, 74, 16, 
	17, 18, 19, 19, 20, 20, 21, 21, 
	22, 23, 24, 40, 23, 24, 40, 25, 
	26, 27, 28, 29, 30, 31, 32, 33, 
	33, 34, 34, 35, 36, 37, 39, 36, 
	37, 39, 37, 23, 38, 38, 41, 42, 
	43, 47, 44, 44, 45, 45, 46, 36, 
	37, 39, 48, 48, 49, 49, 50, 51, 
	51, 52, 53, 55, 56, 57, 57, 58, 
	58, 59, 12, 13, 14, 61, 62, 63, 
	64, 65, 66, 67, 68, 68, 69, 69, 
	70, 71, 71, 72, 73, 74, 1
};

static const char _gt_rule_parser_trans_actions[] = {
	1, 0, 0, 19, 3, 3, 3, 3, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 1, 0, 1, 0, 7, 7, 
	7, 0, 0, 0, 1, 0, 0, 0, 
	0, 0, 0, 1, 0, 1, 0, 1, 
	0, 22, 11, 11, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	1, 0, 1, 0, 15, 15, 15, 0, 
	0, 0, 1, 0, 0, 1, 0, 0, 
	0, 0, 0, 1, 0, 1, 0, 13, 
	13, 13, 0, 1, 0, 1, 17, 17, 
	0, 0, 0, 0, 0, 0, 1, 0, 
	1, 0, 5, 5, 5, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 0, 1, 
	9, 9, 0, 0, 0, 1, 0
};

static const int gt_rule_parser_start = 1;
static const int gt_rule_parser_first_final = 74;
static const int gt_rule_parser_error = 0;

static const int gt_rule_parser_en_main = 1;


#line 34 "src/g-rule-parser.rl"


void gt_print_ruleset( gt_ruleset_t *ruleset )
{
  size_t i, j;

  gt_rule_t   *rules = (gt_rule_t *)ruleset->elts;
  gt_filter_t *filters;

  for( i = 0; i < ruleset->nelts; i++ )
  {    
    printf( "RULE [%p]\n{\n", rules[i] );
    
    filters = (gt_filter_t *)rules[i].chain.elts;
    for( j = 0; j < rules[i].chain.nelts; j++ )
    {
      printf( "  scope      : %s\n"
              "  expression : %s\n"
              "  score      : %.2f\n", filters[j].scope, filters[j].expression, filters[j].score );
              
    }

    printf( "}\n" );
  }
}

u_char *gt_parse_string( gt_parser_t *parser, u_char *p, u_char *pe, u_char *buffer )
{  
  u_char *ptr = buffer;
  size_t   i  = 0;

  do 
  {
    *ptr++ = *p;
    if( ++i > GT_MAX_STRING_SIZE )
    {
      sprintf( parser->error, "String literal above max size %u on line %zu", GT_MAX_STRING_SIZE, parser->lineno );
      return NULL;
    }    
  } 
  while( *(++p) != '"' && p < pe );
  
  *ptr = 0x00;
  
  return p;
}
              
u_char *gt_parse_real( gt_parser_t *parser, u_char *p, u_char *pe, double *pdouble )
{
  size_t neg = 0, 
         dec = 0,
         i   = 0;
              
  *pdouble = 0.0;              
              
  if( *p == '+' )
  {
    ++p;       
    ++i;              
    neg = 0;
  }
  else if( *p == '-' )
  {
    ++p;
    ++i;              
    neg = 1;
  }
              
  for( ; p < pe && ( (*p >= '0' && *p <= '9') || ( *p == '.' && !dec ) ); p++, i++ )
  {
    if( ++i > GT_MAX_STRING_SIZE )
    {
      *pdouble = 0.0;        
      sprintf( parser->error, "Double literal above max size %d on line %d", GT_MAX_STRING_SIZE, parser->lineno );
      return NULL;
    }                
    else if( *p == '.' )
      dec = 1;
    
    else if( dec == 0 )              
      *pdouble = *pdouble * 10 + (*p - '0');
      
    else      
      *pdouble += (*p - '0') / pow( 10.0, dec++ );          
  }
  
  *pdouble = neg ? *pdouble * -1 : *pdouble;              
                
  return p < pe && p ? p - 1 : NULL;
}

void gt_rule_init( gt_parser_t *parser, gt_rule_t *rule )
{
  GT_ZEROIZE( &rule->name );              
  GT_ZEROIZE( &rule->author );     
  rule->threshold = 0.0;   

  ngx_array_init( &rule->chain, parser->pool, 10, sizeof(gt_filter_t) );
}

void gt_filter_init( gt_parser_t *parser, gt_filter_t *filter )
{
  GT_ZEROIZE( &filter->scope );              
  GT_ZEROIZE( &filter->expression );  
  
  memset( &filter->compiled, 0x00, sizeof( ngx_regex_compile_t ) );

  filter->score = 0.0;
}

size_t gt_filter_compile( gt_parser_t *parser, gt_filter_t *filter )
{
  ngx_str_set( &filter->compiled.pattern, filter->expression );

  filter->compiled.pool     = parser->pool;
  filter->compiled.err.len  = GT_MAX_STRING_SIZE;
  filter->compiled.err.data = parser->error;

  if( ngx_regex_compile(&filter->compiled) != NGX_OK ) 
    return GT_PARSER_ERROR;

  return GT_PARSER_SUCCESS;
}

void gt_rule_free( gt_rule_t *rule )
{  
  ngx_array_destroy( &rule->chain );
  GT_ZEROIZE( &rule->name );              
  GT_ZEROIZE( &rule->author );     
  rule->threshold = 0.0;   
}

void gt_parser_init( gt_parser_t *parser, ngx_pool_t *pool )
{
  parser->pool   = pool;
  parser->lineno = 1;
  parser->bsize  = 0;              
  parser->buffer = NULL;            
  parser->filter = NULL;        
  parser->rule   = NULL;
  
  GT_ZEROIZE( &parser->error );
}

size_t gt_parser_readfile( gt_parser_t *parser, ngx_fd_t fd )
{
  if( fd == NGX_INVALID_FILE )
  {
    sprintf( parser->error, "Invalid file descriptor" );                
    return GT_PARSER_ERROR;
  }

  if( ( parser->bsize = lseek( fd, 0, SEEK_END ) ) == -1 )
  {
    sprintf( parser->error, "lseek failed" );                
    return GT_PARSER_ERROR;
  }

  lseek( fd, 0, SEEK_SET );

  parser->buffer = (u_char *)calloc( parser->bsize, 1 );
  if( !parser->buffer )              
  {
    sprintf( parser->error, "Could not allocate memory" );                
    return GT_PARSER_ERROR;
  }          

  if( read( fd, parser->buffer, parser->bsize ) != parser->bsize )
  {
    free( parser->buffer );
    sprintf( parser->error, "Error reading file" );                
    return GT_PARSER_ERROR;
  }

  return GT_PARSER_SUCCESS;
}

void gt_parser_free( gt_parser_t *parser )
{
  if( parser && parser->bsize && parser->buffer )
  {
    free( parser->buffer );
    gt_parser_init( parser, NULL );          
  }
}
              
size_t gt_parse_ruleset( gt_parser_t *parser, gt_ruleset_t *ruleset )
{
  if( !parser->bsize || !parser->buffer )
  {
    sprintf( parser->error, "Invalid input buffer" );              
    return GT_PARSER_ERROR;
  }
        
  int      cs, i;
  u_char  *p  = parser->buffer,
          *pe = parser->buffer + parser->bsize;
                                                        

#line 402 "src/g-rule-parser.c"
	{
	cs = gt_rule_parser_start;
	}

#line 407 "src/g-rule-parser.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _gt_rule_parser_trans_keys + _gt_rule_parser_key_offsets[cs];
	_trans = _gt_rule_parser_index_offsets[cs];

	_klen = _gt_rule_parser_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _gt_rule_parser_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _gt_rule_parser_indicies[_trans];
	cs = _gt_rule_parser_trans_targs[_trans];

	if ( _gt_rule_parser_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _gt_rule_parser_actions + _gt_rule_parser_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 234 "src/g-rule-parser.rl"
	{ 
    if( (*p) == '\n' ) 
      ++parser->lineno; 
  }
	break;
	case 1:
#line 240 "src/g-rule-parser.rl"
	{            
    parser->rule = (gt_rule_t *)ngx_array_push( ruleset );

    gt_rule_init( parser, parser->rule );
  }
	break;
	case 2:
#line 247 "src/g-rule-parser.rl"
	{ 
    GT_PARSER_FILL_STRING( parser->rule->name );    
                              
    {p = (( p))-1;}
  }
	break;
	case 3:
#line 254 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_STRING( parser->rule->author );

    {p = (( p))-1;}
  }
	break;
	case 4:
#line 261 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_REAL( parser->rule->threshold );   
           
    {p = (( p))-1;}
  }
	break;
	case 5:
#line 268 "src/g-rule-parser.rl"
	{    
    parser->filter = (gt_filter_t *)ngx_array_push( &parser->rule->chain );

    gt_filter_init( parser, parser->filter );
  }
	break;
	case 6:
#line 275 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_STRING( parser->filter->scope );
         
    {p = (( p))-1;}              
  }
	break;
	case 7:
#line 282 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_STRING( parser->filter->expression );

    if( gt_filter_compile( parser, parser->filter ) != GT_PARSER_SUCCESS )
      return GT_PARSER_ERROR;
     
    {p = (( p))-1;}              
  }
	break;
	case 8:
#line 292 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_REAL( parser->filter->score );
       
    {p = (( p))-1;}              
  }
	break;
#line 555 "src/g-rule-parser.c"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}

#line 336 "src/g-rule-parser.rl"

              
  if( cs < gt_rule_parser_first_final )
  {
    sprintf( parser->error, "Syntax error on line %d ", parser->lineno );              
    return GT_PARSER_ERROR;
  }
              
  return GT_PARSER_SUCCESS;
}
                   
              
                                                     

