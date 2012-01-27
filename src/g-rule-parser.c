
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
	7, 2, 4, 0
};

static const unsigned char _gt_rule_parser_key_offsets[] = {
	0, 0, 5, 13, 14, 15, 16, 17, 
	18, 23, 28, 30, 32, 38, 38, 39, 
	40, 41, 42, 47, 52, 57, 63, 69, 
	70, 71, 72, 73, 74, 79, 84, 86, 
	88, 94, 100, 100, 101, 102, 104, 105, 
	110, 115, 117, 118, 123, 131, 133, 142, 
	144, 152, 153, 154, 155, 160, 165, 167, 
	168, 169, 170, 171, 172, 173, 174, 175, 
	180, 188, 190, 199, 201, 209
};

static const char _gt_rule_parser_trans_keys[] = {
	13, 32, 123, 9, 10, 13, 32, 97, 
	99, 110, 116, 9, 10, 117, 116, 104, 
	111, 114, 13, 32, 58, 9, 10, 13, 
	32, 34, 9, 10, 34, 92, 34, 92, 
	13, 32, 44, 125, 9, 10, 104, 97, 
	105, 110, 13, 32, 58, 9, 10, 13, 
	32, 91, 9, 10, 13, 32, 123, 9, 
	10, 13, 32, 102, 115, 9, 10, 13, 
	32, 102, 115, 9, 10, 105, 108, 116, 
	101, 114, 13, 32, 58, 9, 10, 13, 
	32, 34, 9, 10, 34, 92, 34, 92, 
	13, 32, 44, 125, 9, 10, 13, 32, 
	44, 93, 9, 10, 99, 111, 112, 114, 
	101, 13, 32, 58, 9, 10, 13, 32, 
	34, 9, 10, 34, 92, 101, 13, 32, 
	58, 9, 10, 13, 32, 43, 45, 9, 
	10, 48, 57, 48, 57, 13, 32, 44, 
	46, 125, 9, 10, 48, 57, 48, 57, 
	13, 32, 44, 125, 9, 10, 48, 57, 
	97, 109, 101, 13, 32, 58, 9, 10, 
	13, 32, 34, 9, 10, 34, 92, 104, 
	114, 101, 115, 104, 111, 108, 100, 13, 
	32, 58, 9, 10, 13, 32, 43, 45, 
	9, 10, 48, 57, 48, 57, 13, 32, 
	44, 46, 125, 9, 10, 48, 57, 48, 
	57, 13, 32, 44, 125, 9, 10, 48, 
	57, 13, 32, 44, 9, 10, 0
};

static const char _gt_rule_parser_single_lengths[] = {
	0, 3, 6, 1, 1, 1, 1, 1, 
	3, 3, 2, 2, 4, 0, 1, 1, 
	1, 1, 3, 3, 3, 4, 4, 1, 
	1, 1, 1, 1, 3, 3, 2, 2, 
	4, 4, 0, 1, 1, 2, 1, 3, 
	3, 2, 1, 3, 4, 0, 5, 0, 
	4, 1, 1, 1, 3, 3, 2, 1, 
	1, 1, 1, 1, 1, 1, 1, 3, 
	4, 0, 5, 0, 4, 3
};

static const char _gt_rule_parser_range_lengths[] = {
	0, 1, 1, 0, 0, 0, 0, 0, 
	1, 1, 0, 0, 1, 0, 0, 0, 
	0, 0, 1, 1, 1, 1, 1, 0, 
	0, 0, 0, 0, 1, 1, 0, 0, 
	1, 1, 0, 0, 0, 0, 0, 1, 
	1, 0, 0, 1, 2, 1, 2, 1, 
	2, 0, 0, 0, 1, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 1, 
	2, 1, 2, 1, 2, 1
};

static const short _gt_rule_parser_index_offsets[] = {
	0, 0, 5, 13, 15, 17, 19, 21, 
	23, 28, 33, 36, 39, 45, 46, 48, 
	50, 52, 54, 59, 64, 69, 75, 81, 
	83, 85, 87, 89, 91, 96, 101, 104, 
	107, 113, 119, 120, 122, 124, 127, 129, 
	134, 139, 142, 144, 149, 156, 158, 166, 
	168, 175, 177, 179, 181, 186, 191, 194, 
	196, 198, 200, 202, 204, 206, 208, 210, 
	215, 222, 224, 232, 234, 241
};

static const char _gt_rule_parser_indicies[] = {
	0, 0, 2, 0, 1, 3, 3, 4, 
	5, 6, 7, 3, 1, 8, 1, 9, 
	1, 10, 1, 11, 1, 12, 1, 13, 
	13, 14, 13, 1, 15, 15, 16, 15, 
	1, 18, 19, 17, 21, 22, 20, 23, 
	23, 2, 24, 23, 1, 20, 25, 1, 
	26, 1, 27, 1, 28, 1, 29, 29, 
	30, 29, 1, 31, 31, 32, 31, 1, 
	33, 33, 34, 33, 1, 35, 35, 36, 
	37, 35, 1, 38, 38, 39, 40, 38, 
	1, 41, 1, 42, 1, 43, 1, 44, 
	1, 45, 1, 46, 46, 47, 46, 1, 
	48, 48, 49, 48, 1, 51, 52, 50, 
	54, 55, 53, 56, 56, 57, 58, 56, 
	1, 59, 59, 32, 21, 59, 1, 53, 
	60, 1, 61, 1, 62, 63, 1, 64, 
	1, 65, 65, 66, 65, 1, 67, 67, 
	68, 67, 1, 70, 71, 69, 72, 1, 
	73, 73, 74, 73, 1, 75, 75, 76, 
	76, 75, 77, 1, 78, 1, 56, 56, 
	57, 79, 58, 56, 78, 1, 80, 1, 
	56, 56, 57, 58, 56, 80, 1, 81, 
	1, 82, 1, 83, 1, 84, 84, 85, 
	84, 1, 86, 86, 87, 86, 1, 89, 
	90, 88, 91, 1, 92, 1, 93, 1, 
	94, 1, 95, 1, 96, 1, 97, 1, 
	98, 1, 99, 99, 100, 99, 1, 101, 
	101, 102, 102, 101, 103, 1, 104, 1, 
	23, 23, 2, 105, 24, 23, 104, 1, 
	106, 1, 23, 23, 2, 24, 23, 106, 
	1, 107, 107, 108, 107, 1, 0
};

static const char _gt_rule_parser_trans_targs[] = {
	1, 0, 2, 2, 3, 14, 49, 55, 
	4, 5, 6, 7, 8, 8, 9, 9, 
	10, 11, 12, 13, 11, 12, 13, 12, 
	69, 15, 16, 17, 18, 18, 19, 19, 
	20, 20, 21, 22, 23, 35, 22, 23, 
	35, 24, 25, 26, 27, 28, 28, 29, 
	29, 30, 31, 32, 34, 31, 32, 34, 
	32, 22, 33, 33, 36, 37, 38, 42, 
	39, 39, 40, 40, 41, 31, 32, 34, 
	43, 43, 44, 44, 45, 46, 46, 47, 
	48, 50, 51, 52, 52, 53, 53, 54, 
	11, 12, 13, 56, 57, 58, 59, 60, 
	61, 62, 63, 63, 64, 64, 65, 66, 
	66, 67, 68, 69, 1
};

static const char _gt_rule_parser_trans_actions[] = {
	1, 0, 0, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 0, 1, 
	0, 5, 5, 5, 0, 0, 0, 1, 
	0, 0, 0, 0, 0, 1, 0, 1, 
	0, 1, 0, 17, 9, 9, 1, 0, 
	0, 0, 0, 0, 0, 0, 1, 0, 
	1, 0, 13, 13, 13, 0, 0, 0, 
	1, 0, 0, 1, 0, 0, 0, 0, 
	0, 1, 0, 1, 0, 11, 11, 11, 
	0, 1, 0, 1, 15, 15, 0, 0, 
	0, 0, 0, 0, 1, 0, 1, 0, 
	3, 3, 3, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 0, 1, 7, 7, 
	0, 0, 0, 1, 0
};

static const int gt_rule_parser_start = 1;
static const int gt_rule_parser_first_final = 69;
static const int gt_rule_parser_error = 0;

static const int gt_rule_parser_en_main = 1;


#line 34 "src/g-rule-parser.rl"


static u_char *gt_parse_string( gt_parser_t *parser, u_char *p, u_char *pe, u_char *buffer )
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
              
static u_char *gt_parse_real( gt_parser_t *parser, u_char *p, u_char *pe, double *pdouble )
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

static gt_filter_t* gt_chain_push( gt_chain_t *chain )
{
  size_t       idx;   
  gt_filter_t *pcurr;              
              
  idx            = chain->nfilters;                
  chain->filters = (gt_filter_t *)realloc( chain->filters, ++chain->nfilters * sizeof(gt_filter_t) );               
  pcurr          = chain->filters + idx;    
              
  GT_ZEROIZE( &pcurr->scope );  
  GT_ZEROIZE( &pcurr->filter );        
  pcurr->score = 0.0;               
              
  return pcurr;              
}
              
static void gt_rule_init( gt_rule_t *rule )
{
  GT_ZEROIZE( &rule->name );              
  GT_ZEROIZE( &rule->author );     
  rule->threshold      = 0.0;              
  rule->chain.nfilters = 0;
  rule->chain.filters  = NULL;    
}

void gt_rule_free( gt_rule_t *rule )
{
  if( rule && rule->chain.nfilters && rule->chain.filters )
  {
    free( rule->chain.filters );
    gt_rule_init( rule );
  }
}

void gt_parser_init( gt_parser_t *parser )
{
  parser->lineno = 1;
  parser->bsize  = 0;              
  parser->buffer = NULL;            
  parser->filter = NULL;              
  GT_ZEROIZE( &parser->error );
}

size_t gt_parser_readfile( gt_parser_t *parser, FILE *fp )
{
  if( !fp )
  {
    sprintf( parser->error, "Invalid file handle" );                
    return GT_PARSER_ERROR;
  }
              
  fseek( fp, 0, SEEK_END );

  parser->bsize = ftell(fp);

  rewind(fp);

  parser->buffer = (u_char *)calloc( parser->bsize, 1 );
  if( !parser->buffer )              
  {
    sprintf( parser->error, "Could not allocate memory" );                
    return GT_PARSER_ERROR;
  }          

  if( fread( parser->buffer, 1, parser->bsize, fp ) != parser->bsize )
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
    gt_parser_init( parser );          
  }
}
              
size_t gt_parse_rule( gt_parser_t *parser, gt_rule_t *rule )
{
  if( !parser->bsize || !parser->buffer )
  {
    sprintf( parser->error, "Invalid input buffer" );              
    return GT_PARSER_ERROR;
  }
              
  int      cs, i;
  u_char  *p  = parser->buffer,
          *pe = parser->buffer + parser->bsize;
                              
  gt_rule_init( rule );              
                          

#line 357 "src/g-rule-parser.c"
	{
	cs = gt_rule_parser_start;
	}

#line 362 "src/g-rule-parser.c"
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
#line 200 "src/g-rule-parser.rl"
	{ 
    if( (*p) == '\n' ) 
      ++parser->lineno; 
  }
	break;
	case 1:
#line 206 "src/g-rule-parser.rl"
	{ 
    GT_PARSER_FILL_STRING( rule->name );                                  
    {p = (( p))-1;}
  }
	break;
	case 2:
#line 212 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_STRING( rule->author );
    {p = (( p))-1;}
  }
	break;
	case 3:
#line 218 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_REAL( rule->threshold );              
    {p = (( p))-1;}
  }
	break;
	case 4:
#line 224 "src/g-rule-parser.rl"
	{          
    parser->filter = gt_chain_push( &rule->chain );          
  }
	break;
	case 5:
#line 229 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_STRING( parser->filter->scope );
         
    {p = (( p))-1;}              
  }
	break;
	case 6:
#line 236 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_STRING( parser->filter->filter );
     
    {p = (( p))-1;}              
  }
	break;
	case 7:
#line 243 "src/g-rule-parser.rl"
	{
    GT_PARSER_FILL_REAL( parser->filter->score );
       
    {p = (( p))-1;}              
  }
	break;
#line 494 "src/g-rule-parser.c"
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

#line 287 "src/g-rule-parser.rl"

              
  if( cs < gt_rule_parser_first_final )
  {
    sprintf( parser->error, "Syntax error on line %d ", parser->lineno );              
    return GT_PARSER_ERROR;
  }
              
  return GT_PARSER_SUCCESS;
}
                   
              
                                                     

