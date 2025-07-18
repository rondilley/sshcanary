/*****
 *
 * Description: main Functions
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
 ****/

/****
 *
 * includes
 *
 ****/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "main.h"

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

PUBLIC volatile sig_atomic_t quit = FALSE;
PUBLIC volatile sig_atomic_t reload = FALSE;
PUBLIC Config_t *config = NULL;

/****
 *
 * external variables
 *
 ****/

extern int errno;
extern char **environ;

/****
 *
 * main function
 *
 ****/

int main(int argc, char *argv[]) {
  PRIVATE int pid = 0;
  PRIVATE int c = 0, i = 0, fds = 0;
  PRIVATE struct passwd *pwd_ent;
  PRIVATE struct group *grp_ent;
  char *pid_file = NULL;
  char *user = NULL;
  char *group = NULL;
#ifdef LINUX
  struct rlimit rlim;

  getrlimit( RLIMIT_CORE, &rlim );
#ifdef DEBUG
  rlim.rlim_cur = rlim.rlim_max;
  printf( "DEBUG - RLIMIT_CORE: %ld\n", rlim.rlim_cur );
#else
  rlim.rlim_cur = 0; 
#endif
  setrlimit( RLIMIT_CORE, &rlim );
#endif

  /* setup config */
  config = ( Config_t * )XMALLOC( sizeof( Config_t ) );
  XMEMSET( config, 0, sizeof( Config_t ) );

  /* store current pid */
  config->cur_pid = getpid();

  /* store current user record */
  config->starting_uid = getuid();
  pwd_ent = getpwuid( config->starting_uid );
  if ( pwd_ent EQ NULL ) {
    fprintf( stderr, "Unable to get user's record\n" );
    endpwent();
    exit( EXIT_FAILURE );
  }
  if ( ( config->home_dir = strdup( pwd_ent->pw_dir ) ) EQ NULL ) {
    fprintf( stderr, "Unable to dup home dir\n" );
    endpwent();
    exit( EXIT_FAILURE );
  }
  endpwent();

  /* get real uid and gid in prep for priv drop */
  config->gid = getgid();
  config->uid = getuid();

  while (1) {
    /* int this_option_optind = optind ? optind : 1; */ /* unused */
#ifdef HAVE_GETOPT_LONG
    int option_index = 0;
    static struct option long_options[] = {
      {"chroot", required_argument, 0, 'c' },
      {"daemon", no_argument, 0, 'D' },
      {"debug", required_argument, 0, 'd' },
      {"help", no_argument, 0, 'h' },
      {"key", required_argument, 0, 'k' },
      {"log", required_argument, 0, 'l' },
      {"listen", required_argument, 0, 'L' },
      {"pid", required_argument, 0, 'P' },
      {"port", required_argument, 0, 'p' },
      {"trap", required_argument, 0, 't' },
      {"user", required_argument, 0, 'u' },
      {"group", required_argument, 0, 'g' },
      {"version", no_argument, 0, 'v' },
      {0, no_argument, 0, 0}
    };
    c = getopt_long(argc, argv, "c:d:Dhk:l:L:P:p:t:u:g:v", long_options, &option_index);
#else
    c = getopt( argc, argv, "c:d:Dhk:l:L:P:p:t:u:g:v" );
#endif

    if (c EQ -1)
      break;

    switch (c) {

    case 'c':
      /* chroot the process into the specific dir */
      if (strlen(optarg) >= PATH_MAX) {
        fprintf(stderr, "ERROR: chroot path too long (max %d chars)\n", PATH_MAX-1);
        cleanup();
        exit(EXIT_FAILURE);
      }
      config->chroot_dir = ( char * )XMALLOC( PATH_MAX );
      XMEMSET( config->chroot_dir, 0, PATH_MAX );
      XSTRNCPY( config->chroot_dir, optarg, PATH_MAX - 1 );
      config->chroot_dir[PATH_MAX - 1] = '\0';

      break;

    case 'd':
      /* show debug info */
      {
        char *endptr;
        long debug_val = strtol(optarg, &endptr, 10);
        if (*endptr != '\0' || debug_val < 0 || debug_val > 9) {
          fprintf(stderr, "ERROR: debug level must be 0-9\n");
          cleanup();
          exit(EXIT_FAILURE);
        }
        config->debug = (int)debug_val;
        config->mode = MODE_INTERACTIVE;
      }
      break;

    case 'D':
        /* run as a daemon */
        config->mode = MODE_DAEMON;
        break;
        
    case 'h':
      /* show help info */
      print_help();
      return( EXIT_SUCCESS );

    case 'k':
      /* define keyfile */
      if (strlen(optarg) >= PATH_MAX) {
        fprintf(stderr, "ERROR: key file path too long (max %d chars)\n", PATH_MAX-1);
        cleanup();
        exit(EXIT_FAILURE);
      }
      config->key_file = ( char * )XMALLOC( PATH_MAX );
      XMEMSET( config->key_file, 0, PATH_MAX );
      XSTRNCPY( config->key_file, optarg, PATH_MAX - 1 );
      config->key_file[PATH_MAX - 1] = '\0';

      break;
      
    case 'l':
      /* define the dir to store logs in */
      if (strlen(optarg) >= PATH_MAX) {
        fprintf(stderr, "ERROR: log file path too long (max %d chars)\n", PATH_MAX-1);
        cleanup();
        exit(EXIT_FAILURE);
      }
      config->log_file = ( char * )XMALLOC( PATH_MAX );
      XMEMSET( config->log_file, 0, PATH_MAX );
      XSTRNCPY( config->log_file, optarg, PATH_MAX - 1 );
      config->log_file[PATH_MAX - 1] = '\0';

      break;

    case 'L':
      /* set the listen address */
      if (strlen(optarg) >= MAXADDRLEN) {
        fprintf(stderr, "ERROR: listen address too long (max %d chars)\n", MAXADDRLEN-1);
        cleanup();
        exit(EXIT_FAILURE);
      }
      config->listen_addr = ( char * )XMALLOC( MAXADDRLEN );
      XMEMSET( config->listen_addr, 0, MAXADDRLEN );
      XSTRNCPY( config->listen_addr, optarg, MAXADDRLEN - 1 );
      config->listen_addr[MAXADDRLEN - 1] = '\0';

      break;
      
    case 'P':
      /* define the location of the pid file used for rotating logs, etc */
      if (strlen(optarg) >= PATH_MAX) {
        fprintf(stderr, "ERROR: pid file path too long (max %d chars)\n", PATH_MAX-1);
        cleanup();
        exit(EXIT_FAILURE);
      }
      pid_file = ( char * )XMALLOC( PATH_MAX );
      XMEMSET( pid_file, 0, PATH_MAX );
      XSTRNCPY( pid_file, optarg, PATH_MAX - 1 );
      pid_file[PATH_MAX - 1] = '\0';

      break;
      
    case 'p':
      /* define tcp port */
      {
        char *endptr;
        long port_val = strtol(optarg, &endptr, 10);
        if (*endptr != '\0' || port_val < 1 || port_val > 65535) {
          fprintf(stderr, "ERROR: port must be 1-65535\n");
          cleanup();
          exit(EXIT_FAILURE);
        }
        config->tcpPort = (int)port_val;
      }

      break;
      
    case 't':
      /* enable traps (random auth success messages) */
      {
        char *endptr;
        long trap_val = strtol(optarg, &endptr, 10);
        if (*endptr != '\0' || trap_val <= 0 || trap_val > 1000000) {
          fprintf(stderr, "ERROR: trap frequency must be 1-1000000\n");
          cleanup();
          exit(EXIT_FAILURE);
        }
        config->trap = (int)trap_val;
      }
        
      break;
        
    case 'u':

      /* set user to run as */
      if (strlen(optarg) >= MAX_USER_LEN) {
        fprintf(stderr, "ERROR: username too long (max %d chars)\n", MAX_USER_LEN-1);
        cleanup();
        exit(EXIT_FAILURE);
      }
      user = ( char * )XMALLOC( MAX_USER_LEN );
      XMEMSET( user, 0, MAX_USER_LEN );
      XSTRNCPY( user, optarg, MAX_USER_LEN - 1 );
      user[MAX_USER_LEN - 1] = '\0';
      if ( ( pwd_ent = getpwnam( user ) ) EQ NULL ) {
	fprintf( stderr, "ERR - Unknown user [%s]\n", user );
	endpwent();
	XFREE( user );
	cleanup();
	exit( EXIT_FAILURE );
      }
      config->uid = pwd_ent->pw_uid;
      endpwent();
      XFREE( user );

      break;

    case 'g':

      /* set gid to run as */
      if (strlen(optarg) >= MAX_GROUP_LEN) {
        fprintf(stderr, "ERROR: group name too long (max %d chars)\n", MAX_GROUP_LEN-1);
        cleanup();
        exit(EXIT_FAILURE);
      }
      group = ( char * )XMALLOC( MAX_GROUP_LEN );
      XMEMSET( group, 0, MAX_GROUP_LEN );
      XSTRNCPY( group, optarg, MAX_GROUP_LEN - 1 );
      group[MAX_GROUP_LEN - 1] = '\0';
      if ( ( grp_ent = getgrnam( group ) ) EQ NULL ) {
	fprintf( stderr, "ERR - Unknown group [%s]\n", group );
	endgrent();
	XFREE( group );
	cleanup();
	exit( EXIT_FAILURE );
      }
      config->gid = grp_ent->gr_gid;
      endgrent();
      XFREE( group );
    
      break;        
      
    case 'v':
      /* show the version */
      print_version();
      return( EXIT_SUCCESS );

    default:
      fprintf( stderr, "Unknown option code [0%o]\n", c);
    }
  }

  /* set default options */
  if ( config->key_file EQ NULL ) {
    config->key_file = ( char * )XMALLOC( strlen( KEYFILE ) + 1 );
    XSTRNCPY( config->key_file, KEYFILE, strlen( KEYFILE ) );
    config->key_file[strlen( KEYFILE )] = '\0';
  }

  if ( config->log_file EQ NULL ) {
    config->log_file = ( char * )XMALLOC( strlen( LOG_FILE ) + 1 );
    XSTRNCPY( config->log_file, LOG_FILE, strlen( LOG_FILE ) );
    config->log_file[strlen( LOG_FILE )] = '\0';
  }

  if ( config->tcpPort EQ 0 )
      config->tcpPort = 22;
  
  if ( pid_file EQ NULL ) {
    pid_file = ( char * )XMALLOC( strlen( PID_FILE ) + 1 );
    XSTRNCPY( pid_file, PID_FILE, strlen( PID_FILE ) );
    pid_file[strlen( PID_FILE )] = '\0';
  }

  if ( config->listen_addr EQ NULL ) {
    config->listen_addr = ( char * )XMALLOC( strlen( LISTENADDR ) + 1 );
    XSTRNCPY( config->listen_addr, LISTENADDR, strlen( LISTENADDR ) );
    config->listen_addr[strlen( LISTENADDR )] = '\0';
  }
  
  /* validate configuration parameters */
  if ( access( config->key_file, R_OK ) != 0 ) {
    display( LOG_ERR, "Cannot read key file [%s]: %s", config->key_file, strerror(errno) );
    cleanup();
    exit( EXIT_FAILURE );
  }
  
#ifdef DEBUG
  if ( config->debug >= 4 ) {
    fprintf( stderr, "PID: %s\n", pid_file );
    fprintf( stderr, "LDIR: %s\n", config->log_file );
  }
#endif

  /* if not interactive, then become a daemon */
  if ( config->mode != MODE_INTERACTIVE ) {
    /* let everyone know we are running */
    fprintf( stderr, "%s v%s [%s - %s] starting in daemon mode\n", PROGNAME, VERSION, __DATE__, __TIME__ );

    /* check if we are already in the background */
    if ( getppid() EQ 1 ) {
      /* already owned by init */
    } else {
      /* ignore terminal signals */
      signal( SIGTTOU, SIG_IGN );
      signal( SIGTTIN, SIG_IGN );
      signal( SIGTSTP, SIG_IGN );

      /* first fork */
      if ( ( pid = fork() ) < 0 ) {
        /* that didn't work, bail */
        fprintf( stderr, "Unable to fork, forker must be broken\n" );
        exit( EXIT_FAILURE );
      } else if ( pid > 0 ) {
        /* this is the parent, quit */
        exit( EXIT_SUCCESS );
      }

      /* this is the first child, confused? */

      /* set process group leader AKA: I AM THE LEADER */
      if ( setpgid( 0, 0 ) != 0 ) {
        fprintf( stderr, "Unable to become the process group leader\n" );
        exit( EXIT_FAILURE );
      }

      /* ignore hup */
      signal( SIGHUP, SIG_IGN );

      /* second fork */
      if ( ( pid = fork() ) < 0 ) {
        /* that didn't work, bail */
        fprintf( stderr, "Unable to fork, forker must be broken\n" );
        exit( EXIT_FAILURE );
      } else if ( pid > 0 ) {
        /* this is the first child, quit */
        exit( EXIT_SUCCESS );
      }

      /* this is the second child, really confused? */

      /* move to '/' */
      if ( chdir( "/" ) EQ FAILED ) {
          fprintf( stderr, "Unable to change directory\n" );
          exit( EXIT_FAILURE );
      }

      /* close all open files */
      if ( ( fds = getdtablesize() ) EQ FAILED ) fds = MAX_FILE_DESC;
      for ( i = 0; i < fds; i++ ) close( i );

      /* reopen stdin, stdout and stderr to the null device */

      /* reset umask */
      umask( 0027 );

      /* stir randoms if used - use secure random source */
      {
        int urandom_fd = open("/dev/urandom", O_RDONLY);
        if (urandom_fd >= 0) {
          unsigned int seed;
          if (read(urandom_fd, &seed, sizeof(seed)) == sizeof(seed)) {
            srand(seed);
          } else {
            /* fallback to time-based if urandom fails */
            srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
          }
          close(urandom_fd);
        } else {
          /* fallback to time-based if no urandom */
          srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
        }
      }
      
      /* done forking off */

      /* enable syslog */
      openlog( PROGNAME, LOG_CONS & LOG_PID, LOG_LOCAL0 );
    }
  } else {
    show_info();
    display( LOG_INFO, "Running in interactive mode" );
  }

  /* write pid to file */
#ifdef DEBUG
  display( LOG_DEBUG, "PID: %s", pid_file );
#endif
  if ( create_pid_file( pid_file ) EQ FAILED ) {
    display( LOG_ERR, "Creation of pid file failed" );
    cleanup();
    exit( EXIT_FAILURE );
  }

  /* check dirs and files for danger */

  /* figure our where our default dir will be */
  if ( config->chroot_dir EQ NULL ) {
    /* if chroot not defined, use user's home dir */
#ifdef DEBUG
    display( LOG_DEBUG, "CWD: %s", config->home_dir );
#endif
    /* move into home dir */
    if ( chdir( config->home_dir ) EQ FAILED ) {
        display( LOG_ERR, "Can't chdir to [%s]", config->home_dir );
        cleanup();
        exit( EXIT_FAILURE );
    }
  } else {
    /* chroot this puppy */
#ifdef DEBUG
    if ( config->debug >= 3 ) {
      display( LOG_DEBUG, "chroot to [%s]", config->chroot_dir );
    }
#endif
    if ( chroot( config->chroot_dir ) != 0 ) {
      display( LOG_ERR, "Can't chroot to [%s]", config->chroot_dir );
      cleanup();
      exit( EXIT_FAILURE );
    }
    if ( chdir( "/" ) EQ FAILED ) {
        display( LOG_ERR, "Can't chdir to [/]" );
        cleanup();
        exit( EXIT_FAILURE );
    }
  }

  /* setup gracefull shutdown */
  signal( SIGINT, sigint_handler );
  signal( SIGTERM, sigterm_handler );
  signal( SIGFPE, sigfpe_handler );
  signal( SIGILL, sigill_handler );
  signal( SIGSEGV, sigsegv_handler );
#ifndef MINGW
  signal( SIGHUP, sighup_handler );
  signal( SIGBUS, sigbus_handler );
#endif

  /* setup current time updater */
  signal( SIGALRM, ctime_prog );
  alarm( 5 );

  if ( time( &config->current_time ) EQ -1 ) {
    display( LOG_ERR, "Unable to get current time" );
    /* cleanup syslog */
    if ( config->mode != MODE_INTERACTIVE ) {
      closelog();
    }
    /* cleanup buffers */
    cleanup();
    return EXIT_FAILURE;
  }

  /* initialize program wide config options */
  config->hostname = (char *)XMALLOC( MAXHOSTNAMELEN+1 );

  /* get processor hostname */
  if ( gethostname( config->hostname, MAXHOSTNAMELEN ) != 0 ) {
    display( LOG_ERR, "Unable to get hostname" );
    strcpy( config->hostname, "unknown" );
  }

  config->cur_pid = getpid();

  /* DROP PRIVILEDGES */
  drop_privileges();
    
  /****
   *
   * lets get this party started
   *
   ****/

  if ( config->mode EQ MODE_INTERACTIVE )
    show_info();
  else
    display( LOG_INFO, "%s v%s [%s - %s] started\n", PROGNAME, VERSION, __DATE__, __TIME__ );
  
  startSshCanary();

  /****
   *
   * we are done
   *
   ****/

  /* cleanup syslog */
  if ( config->mode != MODE_INTERACTIVE ) {
    closelog();
  }

  cleanup();

  return( EXIT_SUCCESS );
}

/****
 *
 * drop privs
 *
 ****/

void drop_privileges( void ) {
  gid_t oldgid = getegid();
  uid_t olduid = geteuid();

#ifdef DEBUG
  if ( config->debug >= 5 ) {
    display( LOG_DEBUG, "dropping privs - uid: %i gid: %i euid: %i egid: %i", config->uid, config->gid, olduid, oldgid );
  }
#endif

  if ( !olduid ) setgroups( 1, &config->gid );

  if ( config->gid != oldgid ) {
    if ( setgid( config->gid ) EQ FAILED ) abort();
  }

  if ( config->uid != olduid ) {
    if ( setuid( config->uid ) EQ FAILED ) abort();
  }

#ifdef DEBUG
  if ( config->debug >= 4 ) {
    display( LOG_DEBUG, "dropped privs - uid: %i gid: %i euid: %i egid: %i", config->uid, config->gid, geteuid(), getegid() );
  }
#endif

  /* verify privilege drop was successful */
  if ( config->gid != oldgid ) {
    if ( getegid() != config->gid ) {
      display( LOG_ERR, "Failed to drop group privileges: expected %d, got %d", config->gid, getegid() );
      abort();
    }
    /* test that we cannot regain old privileges */
    if ( setegid( oldgid ) == 0 ) {
      display( LOG_ERR, "Security error: able to regain old group privileges" );
      abort();
    }
  }
  if ( config->uid != olduid ) {
    if ( geteuid() != config->uid ) {
      display( LOG_ERR, "Failed to drop user privileges: expected %d, got %d", config->uid, geteuid() );
      abort();
    }
    /* test that we cannot regain old privileges */
    if ( seteuid( olduid ) == 0 ) {
      display( LOG_ERR, "Security error: able to regain old user privileges" );
      abort();
    }
  }
}

/****
 *
 * display prog info
 *
 ****/

void show_info( void ) {
  fprintf( stderr, "%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__ );
  fprintf( stderr, "By: Ron Dilley\n" );
  fprintf( stderr, "\n" );
  fprintf( stderr, "%s comes with ABSOLUTELY NO WARRANTY.\n", PROGNAME );
  fprintf( stderr, "This is free software, and you are welcome\n" );
  fprintf( stderr, "to redistribute it under certain conditions;\n" );
  fprintf( stderr, "See the GNU General Public License for details.\n" );
  fprintf( stderr, "\n" );
}

/*****
 *
 * display version info
 *
 *****/

PRIVATE void print_version( void ) {
  printf( "%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__ );
}

/*****
 *
 * print help info
 *
 *****/

PRIVATE void print_help( void ) {
  print_version();

  fprintf( stderr, "\n" );
  fprintf( stderr, "syntax: %s [options]\n", PACKAGE );

#ifdef HAVE_GETOPT_LONG
  fprintf( stderr, " -c|--chroot {dir}    chroot to {dir}\n" );
  fprintf( stderr, " -d|--debug {lvl}     enable debugging info (0-9)\n" );
  fprintf( stderr, " -D|--daemon          run in the background\n" );
  fprintf( stderr, " -h|--help            this info\n" );
  fprintf( stderr, " -k|--key {fname}     filename where ssh key is stored\n" );
  fprintf( stderr, " -l|--log {fname}     filename where events will be logged\n" );
  fprintf( stderr, " -L|--listen {addr}   address to listen on\n" );
  fprintf( stderr, " -p|--port {portnum}  port to listen on (default:22)\n" );
  fprintf( stderr, " -P|--pid {fname}     filename where pid is stored\n" );
  fprintf( stderr, " -t|--trap {freq}     randomly report success (default:%i)\n", TRAP_DEFAULT_PROB );
  fprintf( stderr, " -u|--user {uname}    user to run as\n" );
  fprintf( stderr, " -g|--group {gname}   group to run as\n" );
  fprintf( stderr, " -v|--version         display version information\n" );
#else
  fprintf( stderr, " -c {dir}      chroot to {dir}\n" );
  fprintf( stderr, " -d {lvl}      enable debugging info (0-9)\n" );
  fprintf( stderr, " -D            run in the background\n" );
  fprintf( stderr, " -h            this info\n" );
  fprintf( stderr, " -k {fname}    filename where ssh key is stored\n" );
  fprintf( stderr, " -l {fname}    filename where events will be logged\n" );
  fprintf( stderr, " -L {addr}     address to listen on\n" );
  fprintf( stderr, " -p {portnum}  port to listen on (default:22)\n" );
  fprintf( stderr, " -P {fname}    filename where pid is stored\n" );
  fprintf( stderr, " -t {freq}     randomly report success (default:%i)\n", TRAP_DEFAULT_PROB );
  fprintf( stderr, " -u {uname}    user to run as\n" );
  fprintf( stderr, " -g {gname}    group to run as\n" );
  fprintf( stderr, " -v            display version information\n" );
#endif

  fprintf( stderr, "\n" );
}

/****
 *
 * cleanup
 *
 ****/

PRIVATE void cleanup( void ) {

  XFREE( config->hostname );
  if ( config->home_dir != NULL )
    XFREE( config->home_dir );

  if ( config->outfile != NULL )
    XFREE( config->outfile );

  XFREE( config );
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
}

/****
 *
 * SIGINT handler
 *
 ****/

void sigint_handler( int signo ) {
  /* do a calm shutdown as time permits */
  quit = TRUE;
}

/****
 *
 * SIGTERM handler
 *
 ****/

void sigterm_handler( int signo ) {
  /* do a calm shutdown as time permits */
  quit = TRUE;
}

/****
 *
 * SIGHUP handler
 *
 ****/

#ifndef MINGW
void sighup_handler( int signo ) {
  /* time to rotate logs and check the config */
  reload = TRUE;
}
#endif

/****
 *
 * SIGSEGV handler
 *
 ****/

void sigsegv_handler( int signo ) {
  /* avoid calling non-async-signal-safe functions in signal handler */
  static const char msg[] = "ERR - Caught SIGSEGV, shutting down\n";
  ssize_t result = write(STDERR_FILENO, msg, sizeof(msg) - 1);
  (void)result; /* suppress unused variable warning */
  
  /* core out */
  abort();
}

/****
 *
 * SIGBUS handler
 *
 ****/

void sigbus_handler( int signo ) {
  /* avoid calling non-async-signal-safe functions in signal handler */
  static const char msg[] = "ERR - Caught SIGBUS, shutting down\n";
  ssize_t result = write(STDERR_FILENO, msg, sizeof(msg) - 1);
  (void)result; /* suppress unused variable warning */
  
  /* core out */
  abort();
}

/****
 *
 * SIGILL handler
 *
 ****/

void sigill_handler ( int signo ) {
  /* avoid calling non-async-signal-safe functions in signal handler */
  static const char msg[] = "ERR - Caught SIGILL, shutting down\n";
  ssize_t result = write(STDERR_FILENO, msg, sizeof(msg) - 1);
  (void)result; /* suppress unused variable warning */
  
  /* core out */
  abort();
}

/****
 *
 * SIGFPE handler
 *
 ****/

void sigfpe_handler( int signo ) {
  /* avoid calling non-async-signal-safe functions in signal handler */
  static const char msg[] = "ERR - Caught SIGFPE, shutting down\n";
  ssize_t result = write(STDERR_FILENO, msg, sizeof(msg) - 1);
  (void)result; /* suppress unused variable warning */
  
  /* core out */
  abort();
}

/*****
 *
 * interrupt handler (current time)
 *
 *****/

void ctime_prog( int signo ) {
  /* just update time, avoid complex operations in signal handler */
  time(&config->current_time);
  alarm(5);
}
