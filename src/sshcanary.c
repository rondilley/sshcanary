/*****
 *
 * Description: SSH Canary Functions
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
 * Thanks to Pete Morris (https://github.com/PeteMo) for sshpot which is
 * where the idea of using libssh came from along with his base functions
 * from sshpot (https://github.com/PeteMo/sshpot).  Though I am re-writing
 * much of the his base code to get the additional functionality that I
 * need, his code was foundational for this tool.
 * 
 ****/

/****
 *
 * includes
 *
 ****/

#include "sshcanary.h"
#include <libssh/server.h>

/****
 *
 * local variables
 *
 ****/

/****
 *
 * global variables
 *
 ****/

ssh_session session;
ssh_bind sshbind;

/****
 *
 * external variables
 *
 ****/

extern int quit;
extern int reload;
extern Config_t *config;
extern int errno;
extern char **environ;

/****
 *
 * functions
 *
 ****/

/****
 * 
 * start the ssh listener
 * 
 ****/

int startSshCanary( void ) {
    /* Install the signal handlers to cleanup after children and at exit. */
    signal(SIGCHLD, (void (*)())listener_cleanup);
    signal(SIGINT, (void(*)())wrapup);

    /* Create and configure the ssh session. */
    session=ssh_new();
    sshbind=ssh_bind_new();
    ssh_bind_options_set( sshbind, SSH_BIND_OPTIONS_BINDADDR, config->listen_addr );
    ssh_bind_options_set( sshbind, SSH_BIND_OPTIONS_BINDPORT, &config->tcpPort );
    ssh_bind_options_set( sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa" );
    ssh_bind_options_set( sshbind, SSH_BIND_OPTIONS_RSAKEY, config->key_file );

    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        display( LOG_ERR, "Error listening to socket: %s", ssh_get_error( sshbind ) );
        return( EXIT_FAILURE );
    }
    
#ifdef DEBUG
    if ( config->debug >= 1 )
      display( LOG_DEBUG, "Listening on port %d", config->tcpPort );
#endif
    
    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {
        if (ssh_bind_accept(sshbind, session) EQ SSH_ERROR) {
            display( LOG_ERR, "Error accepting a connection: [%s]", ssh_get_error( sshbind ) );
            return( EXIT_FAILURE );
        }

#ifdef DEBUG
        if (config->debug >= 2 )
            display( LOG_DEBUG, "Accepted a connection" );
#endif
        
        /* update random for trap before fork */
        if ( config->trap )
            config->random = ( rand() % config->trap );
        
#ifdef DEBUG
        if ( config->debug >= 7 )
            display( LOG_DEBUG, "Random: %d", config->random );
#endif
        
        /* XXX need to use IPC to get telemetry back to the parent or handle concurrent connections with threads */
        switch (fork())  {
            case -1:
                display( LOG_ERR, "Forker broken" );
                exit(-1);

            case 0:
                exit(handle_auth(session));

            default:
                break;
        }
    }

    return 0;    
}

/****
 * 
 * Callback when fork() spawns a listener child which waits to be reaped
 * 
 ****/

static int listener_cleanup(void) {
    int status;
    int pid;
    pid_t wait3(int *statusp, int options, struct rusage *rusage);

    while ((pid=wait3(&status, WNOHANG, NULL)) > 0) {
#ifdef DEBUG
        if ( config->debug >= 1 )
            display( LOG_INFO, "process %d reaped", pid);
#endif
    }

    /* Re-install myself for the next child. */
    signal(SIGCHLD, (void (*)())listener_cleanup);

    return 0;
}

/****
 *
 * Shutdown child listener
 * 
 ****/

static void wrapup(void) {
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    exit(0);
}

/****
 * 
 * fills in time/date
 *
 ****/

/* XXX needs to be adjusted to use config->current_time to resude time calls */

static int get_utc(struct connection *c) {
    time_t t;
    t = time(NULL);
    return strftime(c->con_time, MAXBUF, "%Y-%m-%d@%H:%M:%S", gmtime(&t));
}

/****
 *
 * store source specific information
 *
 ****/

/* XXX need to gather other itel from libssh including keys, etc */

static int *get_client_ip(struct connection *c) {
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;

    getpeername(ssh_get_fd(c->session), (struct sockaddr*)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    inet_ntop(AF_INET, &sock->sin_addr, c->client_ip, len);

    return 0;
}

/****
 * 
 * Log connections
 *
 ****/

static int log_attempt(struct connection *c, int message_type ) {
    FILE *f;
    int r;
    ssh_key tmp_ssh_key;
    unsigned char *tmp_hash = NULL;
    size_t *tmp_hlen;
    char tmp_buf[SHA1_HASH_STR_LEN];
    
    /* XXX should only open the file once */
    if ((f = fopen(config->log_file, "a+")) == NULL) {
        display( LOG_ERR, "Unable to open %s", config->log_file );
        return -1;
    }

    if (get_utc(c) <= 0) {
        display( LOG_ERR, "Error getting time");
        return -1;
    }

    if (get_client_ip(c) < 0) {
        display( LOG_ERR, "Error getting client ip");
        return -1;
    }

    c->user = ssh_message_auth_user( c->message );
    if ( message_type EQ SSH_AUTH_METHOD_PASSWORD ) {
        c->pass = ssh_message_auth_password( c->message );
        if ( config->trap && ( config->random EQ 0 ) ) {
#ifdef DEBUG
            if ( config->debug > 6 )
                display( LOG_DEBUG, "Trap set" );
#endif
            r = fprintf( f, "date=%s ip=%s user=%s pw=%s trap\n", c->con_time, c->client_ip, c->user, c->pass );
            ssh_message_auth_reply_success( c->message, 0 );
            /* cleanup message */
            ssh_message_free( c->message );
            c->message = NULL;
        } else
            r = fprintf( f, "date=%s ip=%s user=%s pw=%s\n", c->con_time, c->client_ip, c->user, c->pass );
            
    } else if ( message_type EQ SSH_AUTH_METHOD_PUBLICKEY ) {
        tmp_ssh_key = ssh_message_auth_pubkey( c->message );
#ifdef DEBUG
        if ( config->debug >= 3 )
            display( LOG_DEBUG, "Client presented a %s key", ssh_key_type_to_char( ssh_key_type( tmp_ssh_key ) ) );
#endif
            
        if ( ssh_get_publickey_hash( tmp_ssh_key, SSH_PUBLICKEY_HASH_SHA1, &tmp_hash, tmp_hlen ) < 0 )
            display( LOG_ERR, "Unable to generate hash of public key" );
        else {
            r = fprintf( f, "date=%s ip=%s user=%s keytype=%s key=sha1:%s\n", c->con_time, c->client_ip, c->user, ssh_key_type_to_char( ssh_key_type( tmp_ssh_key ) ), hash2hex( tmp_hash, tmp_buf, *tmp_hlen ) );
            if ( tmp_hash != NULL )
                XFREE( tmp_hash );
            if ( tmp_hlen != NULL )
                XFREE( tmp_hlen );
        }
    }
    return r;
}


/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session) {
    struct connection con;
    con.session = session;
    ssh_gssapi_creds tmp_gssapi_creds;
    
    /* Perform key exchange. */
    if (ssh_handle_key_exchange(con.session)) {
        display( LOG_ERR, "Error exchanging keys: [%s]", ssh_get_error(con.session));
        return -1;
    }
    
#ifdef DEBUG
    if ( config->debug >= 1 )
        display( LOG_DEBUG, "Successful key exchange");
#endif
    
    /* Wait for a message, which should be an authentication attempt. Send the default
     * reply if it isn't. Log the attempt and quit. */
    while (1) {
        if ( ( con.message = ssh_message_get( con.session ) ) EQ NULL ) {
            break;
        }

        switch ( ssh_message_type( con.message ) ) {
          case SSH_REQUEST_AUTH:
                
            // SSH_AUTH_METHOD_UNKNOWN 0
            // SSH_AUTH_METHOD_NONE 0x0001
            // SSH_AUTH_METHOD_PASSWORD 0x0002
            // SSH_AUTH_METHOD_PUBLICKEY 0x0004
            // SSH_AUTH_METHOD_HOSTBASED 0x0008
            // SSH_AUTH_METHOD_INTERACTIVE 0x0010
            // SSH_AUTH_METHOD_GSSAPI_MIC 0x0020

            /* Log the authentication request and disconnect. */
                
            switch( ssh_message_subtype( con.message ) ) {
              case SSH_AUTH_METHOD_PASSWORD:
              case SSH_AUTH_METHOD_PUBLICKEY:
                log_attempt( &con, ssh_message_subtype( con.message ) );
                break;
                        
              case SSH_AUTH_METHOD_NONE:
                display( LOG_INFO, "Client tried to connect without authenticating" );
                break;
                        
              case SSH_AUTH_METHOD_GSSAPI_MIC:
#ifdef HAVE_SSH_GSSAPI_GET_CREDS
                if ( ( tmp_gssapi_creds = ssh_gssapi_get_creds( con.session ) ) != NULL ) {
                    /* client forwarded a token */
                    display( LOG_INFO, "Client forwarded a token" );
                }
#endif
                break;
                        
              default:
                display( LOG_INFO, "SSH Message Sub-Type: %d", ssh_message_subtype( con.message ) );
#ifdef DEBUG
                if ( config->debug >= 1 )
                    display( LOG_DEBUG, "Not a password authentication attempt");
#endif
                break;
            }
            break;

          case SSH_REQUEST_CHANNEL_OPEN:
              display( LOG_INFO, "Client sent channel open message" );
              break;
              
          case SSH_REQUEST_CHANNEL:
              display( LOG_INFO, "Client sent channel message" );
              break;
              
          case SSH_REQUEST_SERVICE:
              display( LOG_INFO, "Client sent service message" );
              /* XXX need to process the service messages */
              break;
              
          case SSH_REQUEST_GLOBAL:
              display( LOG_INFO, "Client sent global message" );
              break;
              
          default:
            display( LOG_INFO, "SSH Message Type: %d", ssh_message_type( con.message ) );
            break;
        }
        
        /* Send the default message regardless of the request type. */
        if ( con.message != NULL ) {
            ssh_message_reply_default( con.message );
            ssh_message_free( con.message );
        }
    }

#ifdef DEBUG
    if ( config->debug >= 1 )
        display( LOG_DEBUG, "Exiting child");
#endif
    
    return 0;
}

/****
 *
 * convert hash to hex
 *
 ****/

char *hash2hex(const unsigned char *hash, char *hashStr, int hLen ) {
  int i;
  char hByte[3];
  bzero( hByte, sizeof( hByte ) );
        hashStr[0] = 0;

  for( i = 0; i < hLen; i++ ) {
    snprintf( hByte, sizeof(hByte), "%02x", hash[i] & 0xff );
#ifdef HAVE_STRNCAT
    strncat( hashStr, hByte, hLen*2 );
#else
    strlcat( hashStr, hByte, hLen*2 );
#endif
  }

  return hashStr;
}
