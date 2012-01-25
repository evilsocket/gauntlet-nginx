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
#include "g-log.h"

static ngx_str_t ngx_gauntlet_error_levels[] = 
{
  ngx_null_string,
  ngx_string("EMERG"),
  ngx_string("ALERT"),
  ngx_string("CRIT"),
  ngx_string("ERROR"),
  ngx_string("WARN"),
  ngx_string("NOTICE"),
  ngx_string("INFO"),
  ngx_string("DEBUG")
};

#if (NGX_HAVE_VARIADIC_MACROS)
void gt_log( ngx_gauntlet_conf_t *cfg, ngx_uint_t level, const char *fmt, ... )
#else
void gt_log( ngx_gauntlet_conf_t *cfg, ngx_uint_t level, const char *fmt, va_list args )
#endif
{
#if (NGX_HAVE_VARIADIC_MACROS)
  va_list  args;
#endif
  u_char   logstr[MAX_LOG_STR], *last, *p;
  
  if( cfg->logfd == NGX_INVALID_FILE )
    return;
  
  last = logstr + MAX_LOG_STR;
  // copy cached date and time
  ngx_memcpy( logstr, ngx_cached_err_log_time.data, ngx_cached_err_log_time.len );
  
  p = logstr + ngx_cached_err_log_time.len;
  // copy error level label
  p = ngx_slprintf( p, last, " [%V] ", &ngx_gauntlet_error_levels[level] );
  
#if (NGX_HAVE_VARIADIC_MACROS)
  
  va_start( args, fmt );
  p = ngx_vslprintf( p, last, fmt, args );
  va_end( args );
  
#else
  
  p = ngx_vslprintf( p, last, fmt, args );
  
#endif
  
  if( p > last - NGX_LINEFEED_SIZE )
    p = last - NGX_LINEFEED_SIZE;
  
  ngx_linefeed(p);
  
  (void)ngx_write_fd( cfg->logfd, logstr, p - logstr );
}

