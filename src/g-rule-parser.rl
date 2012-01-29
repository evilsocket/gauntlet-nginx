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

%%{
  machine gt_rule_parser;
  ws     = [ \t\r\r\n];
  real   = ('+'|'-')?digit+('.'digit+)?;
  string = ( [^"\\] | /\\./ )*;
                              
  write data;              
}%%

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
                                                        
%%{
  action NL 
  { 
    if( fc == '\n' ) 
      ++parser->lineno; 
  }  
  
  action NEW_RULE_ITEM
  {            
    parser->rule = (gt_rule_t *)ngx_array_push( ruleset );

    gt_rule_init( parser, parser->rule );
  }
           
  action SET_RULE_NAME      
  { 
    GT_PARSER_FILL_STRING( parser->rule->name );    
                              
    fexec p;
  }
  
  action SET_RULE_AUTHOR      
  {
    GT_PARSER_FILL_STRING( parser->rule->author );

    fexec p;
  }
  
  action SET_RULE_THRESHOLD
  {
    GT_PARSER_FILL_REAL( parser->rule->threshold );   
           
    fexec p;
  }
 
  action NEW_CHAIN_ITEM
  {    
    parser->filter = (gt_filter_t *)ngx_array_push( &parser->rule->chain );

    gt_filter_init( parser, parser->filter );
  }
              
  action SET_ITEM_SCOPE 
  {
    GT_PARSER_FILL_STRING( parser->filter->scope );
         
    fexec p;              
  }
              
  action SET_ITEM_EXPRESSION
  {
    GT_PARSER_FILL_STRING( parser->filter->expression );

    if( gt_filter_compile( parser, parser->filter ) != GT_PARSER_SUCCESS )
      return GT_PARSER_ERROR;
     
    fexec p;              
  }  
  
  action SET_ITEM_SCORE 
  {
    GT_PARSER_FILL_REAL( parser->filter->score );
       
    fexec p;              
  } 
                
  #              
  # Rule filters chain definitions              
  #  
              
  # filter fields
  TK_SCOPE_FIELD     = "scope"      ws*$NL ':' ws*$NL '"' string >SET_ITEM_SCOPE '"';
  TK_EXPR_FIELD      = "expression" ws*$NL ':' ws*$NL '"' string >SET_ITEM_EXPRESSION '"';
  TK_SCORE_FIELD     = "score"      ws*$NL ':' ws*$NL real       >SET_ITEM_SCORE;                 
  # the list of filter fields            
  TK_ENTRY_FIELD     = ( TK_SCOPE_FIELD | TK_EXPR_FIELD | TK_SCORE_FIELD );              
  TK_ENTRY_FIELDSET  = ws*$NL TK_ENTRY_FIELD ( ws*$NL ',' ws*$NL TK_ENTRY_FIELD )* ws*$NL;  
  # filter block              
  TK_CHAIN_ENTRY     = ws*$NL '{'  TK_ENTRY_FIELDSET >NEW_CHAIN_ITEM '}' ws*$NL;              
  # a set of filters              
  TK_CHAIN_ENTRYSET  = TK_CHAIN_ENTRY ( ',' TK_CHAIN_ENTRY )*;  
              
  # 
  # Rule main definitions
  #
              
  # main fields
  TK_NAME_FIELD      = "name"      ws*$NL ':' ws*$NL '"' string   >SET_RULE_NAME '"';
  TK_AUTHOR_FIELD    = "author"    ws*$NL ':' ws*$NL '"' string   >SET_RULE_AUTHOR '"';
  TK_THRESHOLD_FIELD = "threshold" ws*$NL ':' ws*$NL real         >SET_RULE_THRESHOLD; 
  TK_CHAIN_FIELD     = "chain"     ws*$NL ':' ws*$NL '[' TK_CHAIN_ENTRYSET ']';           
  # the list of fields                                                         
  TK_FIELD           = ( TK_NAME_FIELD | TK_AUTHOR_FIELD | TK_THRESHOLD_FIELD | TK_CHAIN_FIELD );    
  TK_FIELDSET        = ws*$NL TK_FIELD ( ws*$NL ',' ws*$NL TK_FIELD )* ws*$NL;     
  # main rule block       
  TK_RULE            = ws*$NL '{' TK_FIELDSET >NEW_RULE_ITEM '}' ws*$NL;
  # a set of rule blocks
  TK_RULESET         = ws*$NL TK_RULE ( ws*$NL ',' ws*$NL TK_RULE )* ws*$NL;
                                            
  main := TK_RULESET;
  
  write init;
  write exec;
              
}%%
              
  if( cs < gt_rule_parser_first_final )
  {
    sprintf( parser->error, "Syntax error on line %d ", parser->lineno );              
    return GT_PARSER_ERROR;
  }
              
  return GT_PARSER_SUCCESS;
}
                   
              
                                                     

