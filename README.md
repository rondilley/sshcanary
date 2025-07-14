# SSH Canary (sshcanaryd)

by Ron Dilley <ron.dilley@uberadmin.com>

## What is sshcanaryd?

SSH Canary is a ver low interaction honeypot specifically designed to gather
information about potential attackers that attemp to brute-force into a
system using SSH.

## Why use it?

If you are tired of the constant SSH brute-force noise from your IDS and 
installing fail2ban is just too simple for you, you can use SSH Canary to monitor
attackers and better understand the attributes of their campaigns against your
systems.  It is also nice to know if their dictionaries inculde some of your
passwords at the same time.

## Implimentation

Below are the options that sshcanaryd supports.

```
sshcanaryd v0.8 [Jul 14 2025 - 15:38:53]

syntax: sshcanaryd [options]
 -c|--chroot {dir}    chroot to {dir}
 -d|--debug {lvl}     enable debugging info (0-9)
 -D|--daemon          run in the background
 -h|--help            this info
 -k|--key {fname}     filename where ssh key is stored
 -l|--log {fname}     filename where events will be logged
 -L|--listen {addr}   address to listen on
 -p|--port {portnum}  port to listen on (default:22)
 -P|--pid {fname}     filename where pid is stored
 -t|--trap {freq}     randomly report success (default:1000)
 -u|--user {uname}    user to run as
 -g|--group {gname}   group to run as
 -v|--version         display version information
 ```

You must first generate a server key for sshcanary to present when clients connect.

```sh
% ssh-keygen -t rsa -f server.key
```

If you want to run sshcanary as a non-privileged user or in conjuntion with a real 
ssh server, you can use iptables to forward connections to sshcanary on an alternate 
port.

The following forwards all inbound ssh connections destined for TCP/22 to TCP/2222.

```sh
% sudo /sbin/iptables -A PREROUTING -t nat -p tcp --dport 22 -j REDIRECT --to-port 2222
```

When you start sshcanary, use -p 2222 or --port 2222 and all inbound ssh connections 
will be forwarded to your sshcanary.

If you want to allow local connections to a real ssh server from your trusted network 
(e.g. 192.168.10.0/24) but all other ssh connections to be forwarded to your 
sshcanary, you can use iptables to forward connections if they don't originate on 
your trusted network.

```sh
% sudo /sbin/iptables -A PREROUTING -t nat -p tcp -s ! 192.168.10.0/24 --dport 22 -j REDIRECT --to-port 2222
```

A simple and dangerous way to run sshcanary is on the default ssh port as root.

```sh
% sudo sshcanaryd -l /var/sshcanary/server.log -k /var/sshcanary/server.key
```

A better way to run sshcanary is to set an effective UID/GID using the -u|--user and -g|--group options as shown below.

```sh
% sudo sshcanaryd -p 2222 -u sshcanary -g sshcanary -l /var/sshcanary/server.log -k /var/sshcanary/server.key
```

The installation includes an RC script for Linux that starts sshcanary in the above fashion but also enables random "traps" where sshcanary acts like the authentication was successful as seen below.

```sh
% sudo sshcanaryd -p 2222 -u sshcanary -g sshcanary -l /var/sshcanary/server.log -k /var/sshcanary/server.key -t 1000
```

Logging is done in two places, system related events are logged to syslog and authentication events are logged to the specific log file as shown below.

What sshcanary sends to syslog:

```text
Apr 17 12:29:57 server-dev sshcanaryd: sshcanaryd v0.6 [May  1 2021 - 20:57:47] started
Apr 17 12:30:10 server-dev sshcanaryd: Client sent service message
Apr 17 12:42:50 server-dev sshcanaryd: Client sent service message
Apr 17 12:42:50 server-dev sshcanaryd: Client tried to connect without authenticating
Apr 17 12:43:51 server-dev sshcanaryd: Client sent service message
Apr 17 12:43:51 server-dev sshcanaryd: Client tried to connect without authenticating
Apr 17 14:05:12 server-dev sshcanaryd: Error exchanging keys: []
```

What sshrgcanary writes to the log:

```text
date=2021-04-16@23:47:59 ip=91.197.232.103 user=support pw=support
date=2021-04-16@23:48:02 ip=91.197.232.103 user=sysadmin pw=admin
date=2021-04-16@23:48:04 ip=91.197.232.103 user=telecomadmin pw=nE7jA%5m
date=2021-04-16@23:48:06 ip=91.197.232.103 user=telnet pw=admin
date=2021-04-16@23:48:08 ip=91.197.232.103 user=test pw=test
date=2021-04-16@23:48:14 ip=91.197.232.103 user=ubnt pw=ubnt
date=2021-04-16@23:48:16 ip=91.197.232.103 user=user pw=user
date=2021-04-16@23:48:16 ip=91.197.232.103 user=user pw=123456
date=2021-04-16@23:48:16 ip=91.197.232.103 user=user pw=1234
date=2021-04-16@23:48:19 ip=91.197.232.103 user=user1 pw=1234
```

## Compatibility

I have built and tested this tool on the following operating systems:

* Linux (openSUSE v42.1 [32/64bit])
* Linux (CentOS v7.0 [32/64bit])
* Linux (Ubuntu v18.04/20.04 [64bit])
* openBSD (v6.8 [i386])
* FreeBSD (v13 [64bit])
* Mac OS/X (Mavericks/Yosemite)

## Security Implications

Assume that there are errors in the source that would
allow an attacker to gain unauthorized access to your
computer.  Don't trust this software and install and use
it at your own risk.

## Bugs

I am not a programmer by any strech of the imagination.  I
have attempted to remove the obvious bugs and other
programmer related errors but please keep in mind the first
sentence.  If you find an issue with code, please send me
an e-mail with details and I will be happy to look into
it.

Ron Dilley
ron.dilley@uberadmin.com

