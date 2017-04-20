/*****
 *
 * Description: sshcanary Function Headers
 * 
 * Copyright (c) 2016, Ron Dilley
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ****/

#ifndef SSHCANARY_DOT_H
#define SSHCANARY_DOT_H

/****
 *
 * defines
 *
 ****/

#define MIN_PORT 0
#define MAX_PORT 65535
#define MD5_HASH_LEN 16
#define SHA1_HASH_LEN 20
#define MD5_HASH_STR_LEN 33
#define SHA1_HASH_STR_LEN 41
#define MAX_TRY_COUNT 2

/****
 *
 * includes
 *
 ****/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sysdep.h>

#ifndef __SYSDEP_H__
# error something is messed up
#endif

#include <common.h>
#include "util.h"
#include "mem.h"

/****
 *
 * consts & enums
 *
 ****/

#define MAXBUF 100

/****
 *
 * typedefs & structs
 *
 ****/

struct connection {
    ssh_session session;
    ssh_message message;
    char client_ip[MAXBUF+1];
    char con_time[MAXBUF+1];
    char user[MAXBUF+1];
    char pass[MAXBUF+1];
};

/****
 *
 * function prototypes
 *
 ****/

int startSshCanary( void );
static int listener_cleanup(void);
static void wrapup(void);
static int get_utc(struct connection *c);
static int *get_client_ip(struct connection *c);
static int log_attempt(struct connection *c, int message_type);
char *hash2hex(const unsigned char *hash, char *hashStr, int hLen ) ;

int handle_auth(ssh_session session);

#endif /* SSHCANARY_DOT_H */
