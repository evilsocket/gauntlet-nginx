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
#ifndef GAUNTLET_NGINX_H
# define GAUNTLET_NGINX_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/*
 * Default ruleset path if none specified inside the configuration.
 */
#define DEFAULT_RULESET_PATH "/etc/nginx/gauntlet-ruleset.gt"

/*
 * Install the request handler and initialize the module main configuration.
 */
static ngx_int_t ngx_gauntlet_initialize( ngx_conf_t *cf );
/*
 * Create the main configuration.
 */
static void     *ngx_gauntlet_create_main_conf( ngx_conf_t *cf );
/*
 * Create (and initialize) a per-location configuration.
 */
static void     *ngx_gauntlet_create_loc_conf( ngx_conf_t *cf );
/*
 * Merge a new location configuration with the main one.
 */
static char     *ngx_gauntlet_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child );
/*
 * Gauntlet HTTP request handler.
 */
static ngx_int_t ngx_gauntlet_request_handler( ngx_http_request_t *req );

#endif