#!/usr/bin/perl
#
# author: ron dilley
#
# desc: this perl script parses and chews on sshcanary logs
#
# Copyright (C) 2017  Ron A. Dilley
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# ron.dilley@uberadmin.com
#
############################################################################

#
# modules
#
use Getopt::Std;
use FileHandle;

#
# pragmas
#
use strict;

#
# set environment
#
$ENV{PATH} = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/ucb";

#
# turn on autoflush
#
select STDERR; $| = 1;
select STDOUT; $| = 1;

#
# defines
#
$::TRUE = 1;
$::FALSE = 0;
$::FAILED = -1;

$::VERSION = "0.1";
$::PROGNAME = "canary2csv.pl";

%::Config = ();
$::Config{'debug'} = $::FALSE;

#
# main routine
#
if ( &main() != $::TRUE ) {
  exit( 1 );
}

exit( 0 );

############################################################################
#
# sub-routines
#

#
# main routine
#
sub main {
  my $arg;

  #
  # display script banner
  #
  &show_banner();

  #
  # parse command-line
  #
  &parse_command_line();

  # process args that are left
  while( $arg = shift( @::ARGV ) ) {
    &processFile( $arg );
  }

  # done
  return $::TRUE;
}

#
# display banner info
#
sub show_banner {
  print "$::PROGNAME v$::VERSION\n";
  print "By: Ron Dilley\n";
  print "\n";
  print "$::PROGNAME comes with ABSOLUTELY NO WARRANTY.\n";
  print "This is free software, and you are welcome\n";
  print "to redistribute it under certain conditions;\n";
  print "See the GNU General Public License for details.\n";
  print "\n";

  return $::TRUE;
}

#
# display help info
#
sub show_help {
  print "Syntax:\n";
  print "\n";
  print "$::PROGNAME [options] {file} [{file} ...]\n";
  print "\n";
  print "-d {0-9}   Display debug information during program run\n";
  print "\n";

  return $::TRUE;
}

#
# parse command-line arguments
#
sub parse_command_line {
  no strict 'vars';

  if ( getopts( 'd:' ) == $::FALSE ) {
    &show_help();
    return $::FAILED;
  }
  if ( defined $opt_d ) {
    if ( $opt_d > 0 ) {
      # set debug mode
      $::Config{'debug'} = $opt_d;
    }
  }

  return $::TRUE;
}

#
# process file
#
sub processFile {
  my ( $fname ) = @_;
  my $fHandle = new FileHandle;
  my $line;
  my $date;
  my $ip;
  my $user;
  my $pw;
  
  print stderr "Opening [$fname] for read\n";

  if ( $fname eq "-" ) {
    # read from stdin
    if ( ! defined open( $fHandle, "<&STDIN" ) ) {
      print "ERROR - Unable to dup stdin\n";
      return $::FAILED;
    }
  } else {
    if ( ! defined open( $fHandle, "< $fname" ) ) {
      print "ERROR - Unable to open [$fname]\n";
      return $::FAILED;
    }
  }

  while ( $line = <$fHandle> ) {
    chomp( $line );
    # date=2016-02-29 06:41:15 ip=183.3.202.101 user=root pw=4r5t6y7u
    # date=2016-02-29 06:41:16 ip=183.3.202.101 user=root pw=753753
    # date=2016-02-29 06:41:16 ip=183.3.202.101 user=root pw=911.com trap
    # date=2016-02-29 06:41:18 ip=183.3.202.101 user=root pw=95217
    # date=2016-02-29 06:41:18 ip=183.3.202.101 user=root pw=9876
    # date=2016-02-29 06:41:18 ip=183.3.202.101 user=root pw=aaaaaaaaa
    # date=2016-02-29 06:41:21 ip=183.3.202.101 user=root PW=abcabc123...
    
    if ( $line =~ m/^date\=(.*)\sip\=(.*)\suser\=(.*)\spw\=(.*)\strap$/ ) { # < v0.5 trapped
      $date = $1;
      $date =~ tr/@/ /;
      $ip = $2;
      $user = $3;
      $pw = $4;
    } elsif ( $line =~ m/^date\=(.*)\sip\=(.*)\suser\=(.*)\spw\=(.*)$/ ) { # < v0.5
      $date = $1;
      $date =~ tr/@/ /;
      $ip = $2;
      $user = $3;
      $pw = $4;
    } elsif ( $line =~ m/^date\=(.*)\sip\=(.*)\suser\=(.*)\sPW\=(.*)$/ ) { # >= v0.5 trapped
      $date = $1;
      $date =~ tr/@/ /;
      $ip = $2;
      $user = $3;
      $pw = $4;
    }
    print "$date\t$ip\t$user\t$pw\n";
  }

  close( $fHandle );

  return $::TRUE;
}
