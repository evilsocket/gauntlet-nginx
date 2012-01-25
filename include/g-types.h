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
#ifndef GAUNTLET_TYPES_H
# define GAUNTLET_TYPES_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Main configuration structure.
 */
typedef struct
{
  ngx_str_t ruleset;
  ngx_fd_t  rulefd;
  ngx_str_t logfile;
  ngx_fd_t  logfd;
}
ngx_gauntlet_conf_t;
/*
 * Per-location configuration structure.
 */
typedef struct
{
  ngx_flag_t enabled;  
}
ngx_gauntlet_loc_conf_t;

#endif
