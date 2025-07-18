/*****
 *
 * Description: SSH Canary Functions
 * 
 * Copyright (c) 2025, Ron Dilley
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
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

/****
 *
 * local variables
 *
 ****/

// SSH-2.0-OpenSSH_7.5
// SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
// SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u7
// SSH-2.0-OpenSSH_6.4
// SSH-2.0-OpenSSH_8.4
// SSH-2.0-OpenSSH_7.9 FreeBSD-20200214
// SSH-2.0-OpenSSH_6.8 NetBSD_Secure_Shell-20150403-hpn13v14-lpk
// SSH-2.0-nEPfW
// SSH-2.0-dropbear_2018.76

const char *rgBanners[] = {
    "SSH-2.0-OpenSSH_7.5",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2",
    "SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u7",
    "SSH-2.0-OpenSSH_6.4",
    "SSH-2.0-OpenSSH_8.4",
    "SSH-2.0-OpenSSH_7.9 FreeBSD-20200214",
    "SSH-2.0-OpenSSH_6.8 NetBSD_Secure_Shell-20150403-hpn13v14-lpk",
    "SSH-2.0-nEPfW",
    "SSH-2.0-dropbear_2018.76",
    NULL};

#define RGBANNERCOUNT 9

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
 * forward declarations
 *
 ****/

static void listener_cleanup(int signo);
static void wrapup(int signo);
static int get_utc(struct connection *c);
static int get_client_ip(struct connection *c);
static int log_attempt(struct connection *c, int message_type);

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

int startSshCanary(void)
{
    int s;

    /* Install the signal handlers to cleanup after children and at exit. */
    signal(SIGCHLD, listener_cleanup);
    signal(SIGINT, wrapup);

    /* Create and configure the ssh session. */
    session = ssh_new();
    sshbind = ssh_bind_new();

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, config->listen_addr);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &config->tcpPort);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, config->key_file);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, rgBanners[rand() % RGBANNERCOUNT]);

    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0)
    {
        display(LOG_ERR, "Error listening to socket: %s", ssh_get_error(sshbind));
        return (EXIT_FAILURE);
    }

    /* disable bind blocking */
    /* XXX does not appear to stop blocking on ssh_bind_accept, need to switch to FD and select */
    ssh_bind_set_blocking(sshbind, 0);

#ifdef DEBUG
    if (config->debug >= 1)
        display(LOG_DEBUG, "Listening on port %d", config->tcpPort);
#endif

    /* Loop forever, waiting for and handling connection attempts. */
    while (1)
    {
        /* XXX need to switch to FD and select to loop and listen for child messages */
        if ((s = ssh_bind_accept(sshbind, session)) EQ SSH_ERROR)
        {
            display(LOG_ERR, "Error accepting a connection: [%s]", ssh_get_error(sshbind));
            return (EXIT_FAILURE);
        }
        else if (s EQ SSH_OK)
        {

#ifdef DEBUG
            if (config->debug >= 2)
                display(LOG_DEBUG, "Accepted a connection");
#endif

            /* update random for trap before fork */
            if (config->trap)
                config->random = (rand() % config->trap);

#ifdef DEBUG
            if (config->debug >= 7)
                display(LOG_DEBUG, "Random: %d", config->random);
#endif

            /* XXX need to use IPC to get telemetry back to the parent or handle concurrent connections with threads */

            /* XXX if we stop blocking and open a pipe, the children can talk back to the parent */

            switch (fork())
            {
            case -1:
                display(LOG_ERR, "Forker broken");
                exit(-1);

            case 0:
                exit(handle_auth(session));

            default:
                break;
            }
        }
        else
        {
            // did not accept a new connection
            sleep(1);
            display(LOG_DEBUG, "Sleep");
        }
    }

    return 0;
}

/****
 * 
 * Callback when fork() spawns a listener child which waits to be reaped
 * 
 ****/

static void listener_cleanup(int signo)
{
    int status;
    int pid;
    pid_t wait3(int *statusp, int options, struct rusage *rusage);

    while ((pid = wait3(&status, WNOHANG, NULL)) > 0)
    {
#ifdef DEBUG
        if (config->debug >= 1)
            display(LOG_INFO, "process %d reaped", pid);
#endif
    }

    /* Re-install myself for the next child. */
    signal(SIGCHLD, listener_cleanup);
}

/****
 *
 * Shutdown child listener
 * 
 ****/

static void wrapup(int signo)
{
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

/* XXX needs to be adjusted to use config->current_time to reduce time calls */

static int get_utc(struct connection *c)
{
    time_t t;
    t = time(NULL);
    return strftime(c->con_time, MAXBUF, "%Y-%m-%d %H:%M:%S", gmtime(&t));
}

/****
 *
 * store source specific information
 *
 ****/

/* XXX need to gather other intel from libssh including keys, etc */

static int get_client_ip(struct connection *c)
{
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;

    getpeername(ssh_get_fd(c->session), (struct sockaddr *)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    if (inet_ntop(AF_INET, &sock->sin_addr, c->client_ip, MAXBUF) == NULL) {
        /* fallback if inet_ntop fails */
        strncpy(c->client_ip, "unknown", MAXBUF - 1);
        c->client_ip[MAXBUF - 1] = '\0';
    }

    return 0;
}

/****
 * 
 * Log connections
 *
 ****/

static int log_attempt(struct connection *c, int message_type)
{
    FILE *f = NULL;
    int r;
    ssh_key tmp_ssh_key;
    unsigned char *tmp_hash_p = NULL;
    size_t tmp_hlen;
    /* char tmp_buf[SHA1_HASH_STR_LEN]; */ /* unused */

    if ((f = fopen(config->log_file, "a+")) == NULL)
    {
        display(LOG_ERR, "Unable to open %s", config->log_file);
        return -1;
    }

    if (get_utc(c) <= 0)
    {
        display(LOG_ERR, "Error getting time");
        fclose(f);
        return -1;
    }

    if (get_client_ip(c) != 0)
    {
        display(LOG_ERR, "Error getting client ip");
        fclose(f);
        return -1;
    }

    /* safely copy user name with bounds checking */
    const char *auth_user = ssh_message_auth_user(c->message);
    if (auth_user != NULL) {
        size_t user_len = strlen(auth_user);
        if (user_len >= MAXBUF) {
            /* truncate long usernames but keep them null-terminated */
            strncpy(c->user, auth_user, MAXBUF - 1);
            c->user[MAXBUF - 1] = '\0';
        } else {
            strcpy(c->user, auth_user);
        }
    } else {
        strcpy(c->user, "<null>");
    }
    
    if (message_type EQ SSH_AUTH_METHOD_PASSWORD)
    {
        /* safely copy password with bounds checking */
        const char *auth_pass = ssh_message_auth_password(c->message);
        if (auth_pass != NULL) {
            size_t pass_len = strlen(auth_pass);
            if (pass_len >= MAXBUF) {
                /* truncate long passwords but keep them null-terminated */
                strncpy(c->pass, auth_pass, MAXBUF - 1);
                c->pass[MAXBUF - 1] = '\0';
            } else {
                strcpy(c->pass, auth_pass);
            }
        } else {
            strcpy(c->pass, "<null>");
        }
        if (config->trap && (config->random EQ 0))
        {
#ifdef DEBUG
            if (config->debug > 6)
                display(LOG_DEBUG, "Trap set");
#endif
            r = fprintf(f, "date=%s ip=%s USER=%s PW=%s\n", c->con_time, c->client_ip, c->user, c->pass);
            ssh_message_auth_reply_success(c->message, 0);
            /* cleanup message */
            ssh_message_free(c->message);
            c->message = NULL;
        }
        else
            r = fprintf(f, "date=%s ip=%s user=%s pw=%s\n", c->con_time, c->client_ip, c->user, c->pass);
    }
    else if (message_type EQ SSH_AUTH_METHOD_PUBLICKEY)
    {
        tmp_ssh_key = ssh_message_auth_pubkey(c->message);
#ifdef DEBUG
        if (config->debug >= 3)
            display(LOG_DEBUG, "Client presented a %s key", ssh_key_type_to_char(ssh_key_type(tmp_ssh_key)));
#endif

        if (ssh_get_publickey_hash(tmp_ssh_key, SSH_PUBLICKEY_HASH_SHA1, &tmp_hash_p, &tmp_hlen) < 0)
            display(LOG_ERR, "Unable to generate hash of public key");
        else
        {
            r = fprintf(f, "date=%s ip=%s user=%s keytype=%s key=sha1:%s\n", c->con_time, c->client_ip, c->user, ssh_key_type_to_char(ssh_key_type(tmp_ssh_key)), ssh_get_hexa(tmp_hash_p, tmp_hlen));
            if (tmp_hash_p != NULL)
                ssh_clean_pubkey_hash(&tmp_hash_p);
        }
    }

    fclose(f);
    return r;
}

/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session_param)
{
    struct connection con;
    con.session = session_param;
    int try_count = 0;
#ifdef HAVE_SSH_GSSAPI_GET_CREDS
    ssh_gssapi_creds tmp_gssapi_creds;
#endif

    /* Perform key exchange. */
    if (ssh_handle_key_exchange(con.session))
    {
        display(LOG_ERR, "Error exchanging keys: [%s]", ssh_get_error(con.session));
        return -1;
    }

#ifdef DEBUG
    if (config->debug >= 1)
        display(LOG_DEBUG, "Successful key exchange");
#endif

    /* Wait for a message, which should be an authentication attempt. Send the default
     * reply if it isn't. Log the attempt and quit. */
    while (1)
    {
        if ((con.message = ssh_message_get(con.session)) EQ NULL)
        {
            break;
        }

        switch (ssh_message_type(con.message))
        {
        case SSH_REQUEST_AUTH:

            // SSH_AUTH_METHOD_UNKNOWN 0
            // SSH_AUTH_METHOD_NONE 0x0001
            // SSH_AUTH_METHOD_PASSWORD 0x0002
            // SSH_AUTH_METHOD_PUBLICKEY 0x0004
            // SSH_AUTH_METHOD_HOSTBASED 0x0008
            // SSH_AUTH_METHOD_INTERACTIVE 0x0010
            // SSH_AUTH_METHOD_GSSAPI_MIC 0x0020

            /* Log the authentication request and disconnect. */

            switch (ssh_message_subtype(con.message))
            {
            case SSH_AUTH_METHOD_PASSWORD:
            case SSH_AUTH_METHOD_PUBLICKEY:
                try_count++;
                if (try_count > MAX_TRY_COUNT)
                {
                    /* hang up, too many tries */
                    ssh_silent_disconnect(session_param);
                }
                log_attempt(&con, ssh_message_subtype(con.message));

                break;

            case SSH_AUTH_METHOD_NONE:
                display(LOG_INFO, "Client tried to connect without authenticating");
                break;

            case SSH_AUTH_METHOD_GSSAPI_MIC:
#ifdef HAVE_SSH_GSSAPI_GET_CREDS
                if ((tmp_gssapi_creds = ssh_gssapi_get_creds(con.session)) != NULL)
                {
                    /* client forwarded a token */
                    display(LOG_INFO, "Client forwarded a token");
                }
#endif
                break;

            default:
                display(LOG_INFO, "SSH Message Sub-Type: %d", ssh_message_subtype(con.message));
#ifdef DEBUG
                if (config->debug >= 1)
                    display(LOG_DEBUG, "Not a password authentication attempt");
#endif
                break;
            }
            break;

        case SSH_REQUEST_CHANNEL_OPEN:
            display(LOG_INFO, "Client sent channel open message");
            break;

        case SSH_REQUEST_CHANNEL:
            display(LOG_INFO, "Client sent channel message");
            break;

        case SSH_REQUEST_SERVICE:
            display(LOG_INFO, "Client sent service message");
            /* XXX need to process the service messages */
            break;

        case SSH_REQUEST_GLOBAL:
            display(LOG_INFO, "Client sent global message");
            break;

        default:
            display(LOG_INFO, "SSH Message Type: %d", ssh_message_type(con.message));
            break;
        }

        /* Send the default message regardless of the request type. */
        if (con.message != NULL)
        {
            ssh_message_reply_default(con.message);
            ssh_message_free(con.message);
        }
    }

#ifdef DEBUG
    if (config->debug >= 1)
        display(LOG_DEBUG, "Exiting child");
#endif

    return 0;

    // LIBSSH_API const char *ssh_message_channel_request_pty_term(ssh_message msg);
    // LIBSSH_API int ssh_message_channel_request_pty_width(ssh_message msg);
    // LIBSSH_API int ssh_message_channel_request_pty_height(ssh_message msg);
    // LIBSSH_API int ssh_message_channel_request_pty_pxwidth(ssh_message msg);
    // LIBSSH_API int ssh_message_channel_request_pty_pxheight(ssh_message msg);
    // LIBSSH_API const char *ssh_message_channel_request_env_name(ssh_message msg);
    // LIBSSH_API const char *ssh_message_channel_request_env_value(ssh_message msg);
    // LIBSSH_API const char *ssh_message_channel_request_command(ssh_message msg);
    // LIBSSH_API const char *ssh_message_channel_request_subsystem(ssh_message msg);
    // LIBSSH_API int ssh_message_channel_request_x11_single_connection(ssh_message msg);
    // LIBSSH_API const char *ssh_message_channel_request_x11_auth_protocol(ssh_message msg);
    // LIBSSH_API const char *ssh_message_channel_request_x11_auth_cookie(ssh_message msg);
}

/****
 *
 * convert hash to hex
 *
 ****/

char *hash2hex(const unsigned char *hash, char *hashStr, int hLen)
{
    int i;
    char hByte[3];
    bzero(hByte, sizeof(hByte));
    hashStr[0] = 0;

    for (i = 0; i < hLen; i++)
    {
        snprintf(hByte, sizeof(hByte), "%02x", hash[i] & 0xff);
#ifdef HAVE_STRLCAT
        strlcat(hashStr, hByte, hLen * 2 + 1);
#else
        strncat(hashStr, hByte, (hLen * 2) - strlen(hashStr) - 1);
#endif
    }

    return hashStr;
}
