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
#include "g-types.h"
#include "g-nginx.h"
#include "g-rule-parser.h"
#include "g-log.h"

static ngx_http_module_t ngx_gauntlet_module_ctx = 
{
  NULL,                           /* preconfiguration */
  ngx_gauntlet_initialize,        /* postconfiguration */
  ngx_gauntlet_create_main_conf,  /* create main configuration */
  NULL,                           /* init main configuration */
  NULL,                           /* create server configuration */
  NULL,                           /* merge server configuration */
  ngx_gauntlet_create_loc_conf,   /* create location configuration */
  ngx_gauntlet_merge_loc_conf     /* merge location configuration */
};

static ngx_command_t ngx_gauntlet_commands[] =
{
  {
    ngx_string("gauntlet"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof( ngx_gauntlet_loc_conf_t, enabled ),
    NULL
  },
  
  {
    ngx_string("gauntlet-ruleset"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof( ngx_gauntlet_conf_t, ruleset ),
    NULL 
  },
  
  {
    ngx_string("gauntlet-logfile"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof( ngx_gauntlet_conf_t, logfile ),
    NULL 
  },
  
  ngx_null_command
};

ngx_module_t ngx_gauntlet_module = 
{
  NGX_MODULE_V1,
  &ngx_gauntlet_module_ctx, /* module context */
  ngx_gauntlet_commands,    /* module directives */
  NGX_HTTP_MODULE,          /* module type */
  NULL,                     /* init master */
  NULL,                     /* init module */
  NULL,                     /* init process */
  NULL,                     /* init thread */
  NULL,                     /* exit thread */
  NULL,                     /* exit process */
  NULL,                     /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_gauntlet_initialize(ngx_conf_t *cf)
{
  ngx_http_core_main_conf_t *cconf = ngx_http_conf_get_module_main_conf( cf, ngx_http_core_module );
  ngx_gauntlet_conf_t       *gconf = ngx_http_conf_get_module_main_conf( cf, ngx_gauntlet_module );

  if( !cconf || !gconf )
    return NGX_ERROR;    
  /*
   * Open the logfile.
   */
  gconf->logfd = ngx_open_file( gconf->logfile.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS );
  if( gconf->logfd == NGX_INVALID_FILE )
  {
    fprintf( stderr, "[ERROR] Unable open Gauntlet log file at '%s' : %s.\n", gconf->logfile.data, strerror(errno) );
    return NGX_ERROR;    
  }  
  /*
   * Open the ruleset.
   */
  gconf->rulefd = ngx_open_file( gconf->ruleset.data, NGX_FILE_RDONLY, 0, 0);  
  if( gconf->rulefd == NGX_INVALID_FILE ) 
  {
    fprintf( stderr, "[ERROR] Unable to load Gauntlet ruleset from '%s' : %s.\n", gconf->ruleset.data, strerror(errno) );
    return NGX_ERROR;
  }
  /*
   * Finally install the request handler.
   */
  ngx_http_handler_pt *handler_ptr = ngx_array_push( &cconf->phases[NGX_HTTP_CONTENT_PHASE].handlers );  
  if( !handler_ptr )
  {
    fprintf( stderr, "[ERROR] Could not install Gauntlet request handler.\n" );
    return NGX_ERROR;
  }
  
  *handler_ptr = ngx_gauntlet_request_handler;
  
  gt_log( gconf, NGX_LOG_INFO, "Gauntlet module succesfully initialized." );
  
  return NGX_OK;
}

static void *ngx_gauntlet_create_main_conf( ngx_conf_t *cf )
{
  ngx_gauntlet_conf_t *conf = ngx_pcalloc( cf->pool, sizeof(ngx_gauntlet_conf_t) );
  
  if( conf == NULL )
    return NGX_CONF_ERROR;
  
  ngx_str_set( &conf->ruleset, DEFAULT_RULESET_PATH );
  conf->rulefd = NGX_INVALID_FILE;
  
  ngx_str_set( &conf->logfile, DEFAULT_LOGFILE_PATH );
  conf->logfd = NGX_INVALID_FILE;
    
  return conf;

}

static void *ngx_gauntlet_create_loc_conf( ngx_conf_t *cf )
{
  ngx_gauntlet_loc_conf_t *conf = ngx_pcalloc( cf->pool, sizeof(ngx_gauntlet_loc_conf_t) );

  if( conf == NULL )
    return NGX_CONF_ERROR;

  conf->enabled = NGX_CONF_UNSET;

  return conf;
}

static char *ngx_gauntlet_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child )
{
  ngx_gauntlet_loc_conf_t *prev = parent;
  ngx_gauntlet_loc_conf_t *conf = child;

  ngx_conf_merge_value( conf->enabled, prev->enabled, 0 );
  
  return NGX_CONF_OK;
}

ngx_int_t ngx_send_output( ngx_int_t code, ngx_http_request_t *req, u_char *string )
{
  ngx_int_t    rc;
  ngx_buf_t   *buffer;
  ngx_chain_t  chain;
  size_t       slen = strlen( (char *)string );
  
  /* discard request body, since we don't need it here */
  rc = ngx_http_discard_request_body(req);
  
  if (rc != NGX_OK) {
    return rc;
  } 
  
  /* set the 'Content-type' header */
  ngx_str_set( &req->headers_out.content_type, "text/html" );
  
  /* send the header only, if the request type is http 'HEAD' */
  if (req->method == NGX_HTTP_HEAD) 
  {
    req->headers_out.status  = NGX_HTTP_OK;
    return ngx_http_send_header(req);
  }
  
  /* allocate a buffer for your response body */
  buffer = ngx_pcalloc(req->pool, sizeof(ngx_buf_t));
  if ( buffer == NULL )
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  
  /* attach this buffer to the buffer chain */
  chain.buf  = buffer;
  chain.next = NULL;
  
  /* adjust the pointers of the buffer */
  buffer->pos      = string;
  buffer->last     = string + slen;
  buffer->memory   = 1;  /* this buffer is in memory */
  buffer->last_buf = 1;  /* this is the last buffer in the buffer chain */

  /* set the status line */
  req->headers_out.status           = code;
  req->headers_out.content_length_n = slen;
  
  /* send the headers of your response */
  rc = ngx_http_send_header(req);
  
  if (rc == NGX_ERROR || rc > NGX_OK || req->header_only) {
    return rc;
  }
  
  /* send the buffer chain of your response */
  return ngx_http_output_filter(req, &chain);
}

static ngx_int_t ngx_gauntlet_request_handler( ngx_http_request_t *req )
{
  ngx_gauntlet_conf_t     *conf     = ngx_http_get_module_main_conf( req, ngx_gauntlet_module );
  ngx_gauntlet_loc_conf_t *location = ngx_http_get_module_loc_conf( req, ngx_gauntlet_module );
  
  gt_log_debug( conf, "New HTTP request." );
  
  /*
   * If Gauntlet is not enabled for this location decline the request.
   */
  if( !location->enabled )
  {
    gt_log_debug( conf, "Gauntlet is not enabled for this location." );
    return NGX_DECLINED;
  }
  
  gt_log( conf, NGX_LOG_INFO, "%s request from %s.", req->method_name.data, req->connection->addr_text.data );
  
  return ngx_send_output( NGX_HTTP_OK, req, (u_char *)"Hello World from Gauntlet!!!" );
}
