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
#ifndef GAUNTLET_LOG_H
# define GAUNTLET_LOG_H
/*
 * Default log file if none is specified.
 */
#define DEFAULT_LOGFILE_PATH "/var/log/nginx/gauntlet.log"
/*
 * Log string internal buffer max length.
 */
#define MAX_LOG_STR          0xFF
/*
 * Turn to 1 to enable debug log messages.
 */
#define GAUNTLET_DEBUG       0

#if (NGX_HAVE_VARIADIC_MACROS)

void gt_log( ngx_gauntlet_conf_t *cfg, ngx_uint_t level, const char *fmt, ... );

#if (GAUNTLET_DEBUG)
# define gt_log_debug( cfg, ... ) gt_log( cfg, NGX_LOG_DEBUG, __VA_ARGS__ )     
#else
# define gt_log_debug( cfg, ... ) // 
#endif

#else

void gt_log( ngx_gauntlet_conf_t *cfg, ngx_uint_t level, const char *fmt, va_list args );

#define gt_log_debug( cfg, ... ) // 

#endif

#endif
