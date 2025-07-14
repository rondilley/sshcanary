dnl Process this file with autoconf to produce a configure script
m4_include([version.m4])
AC_PREREQ([2.59])
AC_INIT([SSH Canary], VERSION_NUMBER, [ron.dilley@uberadmin.com], [sshcanaryd], [http://www.uberadmin.com/Projects/sshcanary/])
AC_CONFIG_SRCDIR(src/main.c)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE

dnl Checks for programs
AC_PROG_CC

dnl make /usr/local as the default install dir
AC_PREFIX_DEFAULT(/usr/local)

# Security hardening flags
SECURITY_CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wformat -Wformat-security"
SECURITY_LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now"

# Warning flags
WARNING_CFLAGS="-Wall -Wextra -Wno-unused-parameter -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes"

CFLAGS="${CFLAGS} -I. -I.. -I../include ${SECURITY_CFLAGS} ${WARNING_CFLAGS}"
LDFLAGS="${LDFLAGS} ${SECURITY_LDFLAGS}"

SPLINT="no"
AC_ARG_ENABLE(splint,
    [  --enable-splint         Debug the code with splint],
	SPLINT="yes"      
	CC="splint -D -I"
    ,)

DEBUG="no"
AC_ARG_ENABLE(debug,
    [  --enable-debug          Enable debugging],
    [ if test "$GCC" = yes; then
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG -ggdb -O0"
          # Remove optimization and some hardening for debugging
          SECURITY_CFLAGS=`echo $SECURITY_CFLAGS | sed 's/-D_FORTIFY_SOURCE=2//'`
      else
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG"
      fi
    ],[if test "$GCC" = yes; then
          # Add optimization for release builds
          CFLAGS="${CFLAGS} -O2"
      fi
    ])

MEM_DEBUG="no"
AC_ARG_ENABLE(memdebug,
    [  --enable-memdebug       Enable memory debugging],
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG"
    ,)

SHOW_MEM_DEBUG="no"
AC_ARG_ENABLE(showmemdebug,
    [  --enable-showmemdebug   Enable verbose memory debugging],
      SHOW_MEM_DEBUG="yes"
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG -DSHOW_MEM_DEBUG"
    ,)

GPROF="no"
AC_ARG_ENABLE(gprof,
    [  --enable-gprof          Enable profiler],
    [ if test "$GCC" = yes; then
          GPROF="yes"
          CFLAGS="${CFLAGS} -DGPROF -pg"
      else
          GPROF="yes"
          CFLAGS="${CFLAGS} -DGPROF"
      fi
    ],)

dnl ############# System Dependencies

AC_MSG_CHECKING([for special system dependencies])

AC_CANONICAL_HOST
AC_C_CONST
AC_PROG_GCC_TRADITIONAL

dnl Checks for OS type.
case "$host" in
    *-freebsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([FREEBSD],1,FREEBSD)
        AC_DEFINE([_BSD_SOURCE],1,_BSD_SOURCE)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-netbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([NETBSD],1,NETBSD)
	AC_DEFINE([__USE_BSD],1,__USE_BSD)
	AC_DEFINE([__FAVOR_BSD],1,__FAVOR_BSD)
        ;;
    *-openbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([OPENBSD],1,OPENBSD)
	AC_DEFINE([__USE_BSD],1,__USE_BSD)
	AC_DEFINE([__FAVOR_BSD],1,__FAVOR_BSD)
	AC_DEFINE([_BSD_SOURCE],1,_BSD_SOURCE)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-apple*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([MACOS],1,MACOS)
	AC_DEFINE([_GNU_SOURCE],1,_GNU_SOURCE)
	AC_DEFINE([FTW_STOP],1,FTW_STOP)
	AC_DEFINE([FTW_CONTINUE],0,FTW_CONTINUE)
	AC_DEFINE([FTW_ACTIONRETVAL],16,FTW_ACTIONRETVAL)
        LDFLAGS="${LDFLAGS}"
        ;;
    *-linux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([LINUX],1,LINUX)
	AC_DEFINE([__USE_BSD],1,__USE_BSD)
	AC_DEFINE([_GNU_SOURCE],1,_GNU_SOURCE)
	AC_DEFINE([__FAVOR_BSD],1,__FAVOR_BSD)
	CFLAGS="${CFLAGS} `getconf LFS64_CFLAGS`"
	LDFLAGS="${LDFLAGS} `getconf LFS64_LDFLAGS` `getconf LFS64_LIBS`"
        ;;
    *-cygwin)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([CYGWIN],1,CYGWIN)
	;;
    *-solaris2.10)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([SOLARIS],1,SOLARIS)
	AC_DEFINE([SOLARIS10],1,SOLARIS10)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-solaris*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([SOLARIS],1,SOLARIS)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-mingw*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([MINGW],1,MINGW)
	LDFLAGS="${LDFLAGS} -L/c/MinGW/lib -L/c/MinGW/lib/gcc/mingw32/4.6.2 -lmingw32 -lntdll"
        CFLAGS="${CFLAGS} -I/c/MinGW/include -I/c/MinGW/lib/gcc/mingw32/4.6.2/include"
        ;;
    *-cygwin)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([CYGWIN],1,CYGWIN)
        ;;
    *-aix*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([AIX],1,AIX)
        ;;
    *-hpux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([HPUX],1,HPUX)
        ;;
esac

dnl libssh

AC_ARG_WITH(libssh,
[  --with-libssh=PATH      Specify path to libssh library.],
    [
        AC_MSG_CHECKING(for --with-libssh option)
        case "$withval" in
          yes|no)
            AC_MSG_ERROR(PATH required with libssh option)
            ;;
          *)
            if test '!' -d "$withval"; then
                AC_MSG_ERROR($withval does not exist!)
            else
                AC_MSG_RESULT($withval)
                if test -d "$withval/include/libssh"; then
                  CFLAGS="-I$withval/include -I$withval/include/libssh ${CFLAGS}"
                  CPPFLAGS="-I$withval/include -I$withval/include/libssh ${CPPFLAGS}"
                else
                  CFLAGS="-I$withval ${CFLAGS}"
                  CPPFLAGS="-I$withval ${CPPFLAGS}"
                fi
                if test -d "$withval/lib"; then
                  LDFLAGS="-L$withval/lib ${LDFLAGS}"
                else
                  LDFLAGS="-L$withval ${LDFLAGS}"
                fi
            fi
            ;;
          esac
    ]
)

dnl Checks for libraries

AC_CHECK_HEADERS([libssh/libssh.h],,LIBSSH="no")
if test "$LIBSSH" = "no"; then
   echo ""
   echo "Error: Can't find libssh.h for libssh. Visit http://www.libssh.org for the latest version."
   exit;
fi

AC_CHECK_HEADER([libssh/server.h],,LIBSSH="no")
if test "$LIBSSH" = "no"; then
    echo ""
    echo "Error: Can't find server.h for libssh. Visit http://www.libssh.org for the latest version."
    exit;
fi

AC_CHECK_LIB([ssh],ssh_new,LIBSSH="yes",LIBSSH="no")
if test "$LIBSSH" = "no"; then
    echo ""
    echo "Error: Can't find ssh_new() from libssh. Visit http://www.libssh.org for the latest version."
    exit;
fi

dnl ############## Header Checks

AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([inttypes.h])
AC_CHECK_HEADERS([libintl.h])
AC_CHECK_HEADERS([memory.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([paths.h])
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([sys/resource.h])
AC_CHECK_HEADERS([sys/wait.h])
AC_CHECK_HEADERS([sys/stat.h])
AC_CHECK_HEADERS([grp.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([stdbool.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([wchar.h])
AC_CHECK_HEADERS([ftw.h])
AC_CHECK_HEADERS([pwd.h])
AC_CHECK_HEADERS([signal.h])
AC_CHECK_HEADERS([utime.h])
AC_HEADER_DIRENT
AC_HEADER_STDBOOL


dnl ############## Function checks

AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([getpwuid])
AC_CHECK_FUNCS([endpwent])
AC_CHECK_FUNCS([fchdir])
AC_CHECK_FUNCS([getcwd])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([gethostname])
AC_CHECK_FUNCS([opendir])
AC_CHECK_FUNCS([fstat])
AC_CHECK_FUNCS([strncat])
AC_CHECK_FUNCS([strlcat])
AC_CHECK_FUNCS([snprintf])
AC_CHECK_FUNCS([setrlimit])
AC_CHECK_FUNCS([ftruncate]) 
AC_CHECK_FUNCS([realpath])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([utime])
AC_CHECK_FUNCS([getopt_long])
AC_CHECK_FUNCS([alarm])
AC_CHECK_FUNCS([endgrent])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([ssh_gssapi_get_creds])
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_LSTAT
AC_FUNC_MEMCMP
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_FORK
AC_FUNC_WAIT3

dnl ############## Type checks

AC_TYPE_INT16_T
AC_TYPE_INT64_T
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_UINT8_T
AC_STRUCT_TM
AC_STRUCT_ST_BLOCKS
AC_TYPE_OFF_T
AC_TYPE_SIGNAL

dnl Checks for pointer size
AC_CHECK_SIZEOF(void*, 4)

if test "x$ac_cv_sizeof_voidp" != "x"; then
    if test "$ac_cv_sizeof_voidp" = "4"; then
        AC_DEFINE([BUILD32BIT], [1], [32bit Build])
    elif test "$ac_cv_sizeof_voidp" = "8"; then
	AC_DEFINE([BUILD64BIT], [1], [64bit Build])
    else
	AC_ERROR([Cannot recognize size of void*])
    fi
else
    AC_ERROR([Cannot determine size of void*])
fi

AM_CONFIG_HEADER(include/config.h)
AC_PROG_INSTALL
AC_OUTPUT(Makefile src/Makefile sshcanaryd.1)

echo "Security hardening flags  : ${SECURITY_CFLAGS}"
echo "Warning flags            : ${WARNING_CFLAGS}"

BINDIR=`eval echo ${bindir}`; BINDIR=`eval echo ${BINDIR}`;
MANDIR=`eval echo ${mandir}/${mansubdir}`; MANDIR=`eval echo ${MANDIR}`;

echo ""
echo "-----------------------------------------------"
echo "Host type             : ${host}"
echo "Compiler              : ${CC}"
echo "Compiler flags        : ${CFLAGS}"
echo "Linker flags          : ${LDFLAGS}"
echo "Libraries             : ${LIBS}"
echo ""
echo "Binary                : ${BINDIR}"
echo "Manual pages          : ${MANDIR}"
echo ""
echo "Enable debugging      : ${DEBUG}"
echo "Enable mem debugging  : ${MEM_DEBUG}"
echo "Show mem debugging    : ${SHOW_MEM_DEBUG}"
echo "-----------------------------------------------"
echo ""
