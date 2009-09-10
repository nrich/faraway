#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Std qw/getopts/;
use POSIX qw/:sys_wait_h strftime/;
use Config::Tiny qw//;
use Fcntl qw/:flock/;
use Time::HiRes qw/usleep/;
use File::Basename qw/basename/;
use Sys::Hostname qw/hostname/;
use Data::Dumper qw/Dumper/;
use MIME::Base64 qw/decode_base64 encode_base64/;

use constant CONFIG_DEFAULT => '/etc/faraway/faraway.conf';
use constant LOG_DEFAULT => '/tmp/faraway.log';
use constant PROCESSES_DEFAULT => 3;
use constant LISTEN_DEFAULT => '127.0.0.1';
use constant PORT_DEFAULT => 9095;
use constant SSL_DEFAULT => 9096;
use constant CHILD_LIFETIME => 100;
use constant SSL_KEY_FILE => '/etc/faraway/certs/server-key.pem';
use constant SSL_CERT_FILE => '/etc/faraway/certs/server-cert.pem';
use constant FORWARDS_FILE => '/etc/faraway/forwards.conf';

my $VERBOSE;
my $IS_PARENT = 1;
my $LOG_FILE;
my %opts = ();
my %children = ();
my $FULLPATH = $0;
my $TYPE;

my %ForwardMap = ();

my $NO_ERROR            = 0;
my $UNKNOWN             = 1;

my $NO_REQUEST          = 2;

my $NO_TIMESTAMP        = 3;
my $BAD_TIMESTAMP       = 4;
my $TIME_MISMATCH       = 5;

my $NO_CHECKSUM         = 6;
my $CHECKSUM_MISMATCH   = 7;

my $UNKNOWN_METHOD      = 8;

my $PARSE_ERROR         = 9; 
my $REQUEST_FAILED      = 10;

my %ERROR_MAP = (
    $UNKNOWN => 'Unknown error',

    $NO_REQUEST => 'No request defined',

    $NO_TIMESTAMP => 'No timestamp defined',
    $BAD_TIMESTAMP => 'Bad timestamp',
    $TIME_MISMATCH => 'Timestamp mismatch too great',
    
    $NO_CHECKSUM => 'No checksum defined',
    $CHECKSUM_MISMATCH => 'Checksum mismatch',

    $UNKNOWN_METHOD => 'Unknown method',

    $PARSE_ERROR => 'Request could not be parsed',
    $REQUEST_FAILED => 'Request failed',
);

sub REAPER {
    while ((my $child = waitpid(-1, WNOHANG)) > 0) {
	say("Reaping child $child\n");
	delete $children{$child};
    }

    $SIG{CHLD} = \&REAPER;
}

sub WARN {
    my ($warning) = @_;

    say('WARNING ' . $warning);
}

sub DIE {
    my ($err) = @_;

    say('FATAL ' . $err);
    die $err;
}

sub kill_children {
    for my $child (keys %children) {
	kill 'INT' => $child;
    }
}

getopts('hdsxvc:a:p:f:l:t:', \%opts);
main(@ARGV);

sub main {
    $opts{h} and usage();

    my $config = Config::Tiny->read($opts{c} || CONFIG_DEFAULT);

    $opts{d}||$config->{_}->{daemon} and daemonise();
    my $address = $opts{a} || $config->{_}->{address} || LISTEN_DEFAULT;
    my $port = $opts{p} || $config->{_}->{port};
    my $childcount = $opts{f} || $config->{_}->{children} || PROCESSES_DEFAULT;
    my $use_ssl = $opts{s} || $config->{_}->{ssl} || 0;
    my $use_xml = $opts{x} || $config->{_}->{xml} || 0;
    $LOG_FILE = $opts{l} || $config->{_}->{log} || LOG_DEFAULT;
    $VERBOSE = $opts{v} || $config->{_}->{verbose} || 0;
    $TYPE = $opts{t} || $config->{_}->{type} || hostname();
 
    my $use_auth = $config->{Authentication}->{enable} || 0;
    my $username = $config->{Authentication}->{username} || '';
    my $password = $config->{Authentication}->{password} || '';
    my %blessed_ips = map {$_ => 1} split(',', $config->{Authentication}->{allowed}||'');

    my $daemon;

    $port ||= $use_ssl ? SSL_DEFAULT : PORT_DEFAULT;

    if ($use_ssl) {
	require HTTP::Daemon::SSL;

	$daemon = HTTP::Daemon::SSL->new(
            SSL_key_file => $config->{SSL}->{key} || SSL_KEY_FILE,
            SSL_cert_file => $config->{SSL}->{cert} || SSL_CERT_FILE,
	    LocalPort => $port,
	    LocalAddr => $address,
	    Reuse => 1,
	    Timeout => 300,
	) or die "Could not create HTTPS listener: $!";
    } else {
	require HTTP::Daemon;

	$daemon = HTTP::Daemon->new( 
	    LocalPort => $port, 
	    LocalAddr => $address, 
	    Reuse => 1, 
	    Timeout => 300, 
	) or die "Could not create HTTP listener: $!";
    }

    $SIG{CHLD} = \&REAPER;
    $SIG{__WARN__} = \&WARN;
    $SIG{__DIE__} = \&DIE;

    $SIG{TERM} = $SIG{INT} = $SIG{HUP} = sub {
	my ($sig) = @_;

	if ($IS_PARENT) {
	    say('Closing');

	    kill_children();

	    sleep 1;
	}

	exit 0;
    };

    $SIG{USR1} = sub {
	if ($IS_PARENT) {
	    say('Respawning children');
    
	    kill_children();
	}
    };

    say("Using authentication") if $VERBOSE and $use_auth;

    my $auth_callback = sub {
        my ($authstring, $ip) = @_;

        $authstring =~ s/Basic\s+(.+)$/$1/;

        return 1 unless $use_auth;
        return 1 if $blessed_ips{$ip};

        my $pass = encode_base64("$username:$password");
        chomp $pass;

        return 1 if $authstring and $pass eq $authstring;
            
        return 0;
    };

    my @name = qw/PARENT/;
    push @name, 'SSL' if $use_ssl;
    push @name, 'XML' if $use_xml;
    push @name, "$address:$port";
    set_name(join ' ', @name);

    while (1) {
	while (keys %children < $childcount) {
	    spawn_child($daemon, $use_xml, $auth_callback);
	}

	sleep 1;

	foreach my $child (keys %children) {
	    unless (kill 0 => $child) {
		say("Child $child has died");
		delete $children{$child};
	    }
	}

	sleep 1;
    }
}

sub usage {
    print <<EOF;
Usage: $0 
    [-v(verbose)]
    [-d(aemonise)] 
    [-s(sl)]
    [-x(ml)]
    [-f processes|@{[PROCESSES_DEFAULT]}] 
    [-c config|'@{[CONFIG_DEFAULT]}'] 
    [-l log|'@{[LOG_DEFAULT]}']
    [-a address|'@{[LISTEN_DEFAULT]}'] 
    [-p port|@{[PORT_DEFAULT]}] 
    [-t type|@{[hostname()]}]
EOF

    exit -1;
}

sub say {
    my ($line) = @_;

    $line ||= '';

    chomp $line;

    my $ts = strftime '%Y-%m-%d %H:%M:%S', localtime(); 

    my $out = "$ts [$$] $line\n";

    open my $fh, '>>', $LOG_FILE or die "Cannot open `$LOG_FILE': $!";
    flock $fh, LOCK_EX;
    print $out unless $opts{d};
    print $fh $out;
    close $fh;
}

sub daemonise {
    my $pid; 

    if ($pid = fork()) {
	print $pid, "\n";
	exit 0;
    }

    open STDERR, '>', '/dev/null';
    open STDOUT, '>', '/dev/null';
    open STDIN, '>', '/dev/null';
}

sub create_handler {
    my $serverconf = "/etc/faraway/classes/$TYPE"; 

    my @packages = qw/Faraway::Handler/;
    if (open my $fh, '<', $serverconf) {
	while (my $module = <$fh>) {
	    chomp $module;

	    $module =~ s/^\s+//;
	    $module =~ s/\s+$//;

	    next unless $module;

	    push @packages, "Faraway::Handler::$module";
	}
	close $fh;
    } else {
	warn "Could not read `$serverconf': $! (using defaults)";
    }

    my $parents = join (' ', @packages);

    my $package = "Faraway::Server::$TYPE";

    my $package_build =<<EOF;
package $package;
use base qw/$parents/;

1;

EOF

    eval $package_build;

    # this thrashes if there is a compile error in any
    # of the included composing classes
    sleep 5 and die $@ if $@;

    return $package->new(Logger => \&say);
}

sub load_forwards {
    unless (-f FORWARDS_FILE) {
        say("No forwards file exists in `@{[FORWARDS_FILE]}'");
        return;
    }

    my $fh = undef;
    unless (open $fh, '<', FORWARDS_FILE) {
        say("Cannot open `@{[FORWARDS_FILE]}':  $!");
        return;
    }

    my $current = {};
    while (my $line = <$fh>) {
        chomp $line;

        next unless $line;

        if ($line =~ /^([\S]+)\s*{\s*$/) {
            $current->{name} = $current->{action} = $1;
            say("Got action $1\n");
        } elsif ($line =~ /^\s+(host|port|ssl|xml|username|password|action)\s+=>\s+(.+?)\s*$/) {
            $current->{$1} = $2;
            say("$1 => $2");
        } elsif ($line =~ /^\s*}\s*$/) {
            $ForwardMap{delete $current->{name}} = $current;

            $current = {};
        }
    }

    close $fh;
}

sub spawn_child {
    my ($daemon, $use_xml, $auth_callback) = @_;

    my $pid = fork();

    if ($pid) {
	say("Spawn child $pid\n");
	$children{$pid} = 1;
    } elsif (defined $pid) {
	$IS_PARENT = 0;

	set_name('CHILD IDLE');

	my $handler = create_handler();
        load_forwards();

	my $requests = 0;

	while (++$requests < CHILD_LIFETIME) {
	    my $connection = $daemon->accept() or last;
	    $connection->autoflush(1);
	    #say('Connection from ' . $connection->peerhost());

	    # Get the request
	    my $request = $connection->get_request() or last;
	    my $url = $request->url();
	    my $action = substr($url, 1);

            if (!$auth_callback->($request->header('Authorization')||'', $connection->peerhost())) {
                if (!$request->header('Authorization')) {
                    my $auth = HTTP::Response->new(401, 'Unauthorized');
                    $auth->header('WWW-Authenticate' => 'Basic realm="Faraway"');
                    $auth->is_error(1);
                    $auth->error_as_HTML(1);
                    $connection->send_response($auth);
                    $connection->close();
                } else {
                    $connection->send_error(403);
                    $connection->close();
                }
                next;
            }

	    my $content = $request->content();
	    say($content) if $VERBOSE;
	    my $data = process_request($handler, $connection->peerhost(), $action, $content, $use_xml);
	    say($data) if $VERBOSE;

	    my $response = HTTP::Response->new(200);

	    $response->content($data);
	    $response->header('Content-Type' => $use_xml ? 'application/xml' : 'application/json');
	    $connection->send_response($response);
	    $connection->close();

	    set_name('CHILD IDLE');
	}

	say('Child is done');

	exit 0;
    } else {
	die "Fork failed: $!\n";
    }
}

sub set_name {
    my ($extra) = @_;

    my $script = basename $FULLPATH;

    $0 = "$script $extra";
}

sub error {
    my ($code) = @_;

    die $ERROR_MAP{$code||$UNKNOWN};
}

sub decode {
    my ($string, $use_xml) = @_;

    if ($use_xml) {
	require XML::Simple;
	return XML::Simple::XMLin($string);
    } else {
	require JSON;
	return JSON::from_json($string);
    }
}

sub encode {
    my ($obj, $use_xml) = @_;

    if ($use_xml) {
	require XML::Simple;
	return XML::Simple::XMLout($obj);
    } else {
	require JSON;
	return JSON::to_json($obj);
    }
}

sub process_request  {
    my ($handler, $ip, $request, $string, $use_xml) = @_;

    my $err = $PARSE_ERROR;
    my $res = {};

    set_name("CHILD $request");

    eval {
        my $obj = decode($string, $use_xml);

        # JSON decoded OK, all errors in subs now
        $err = $REQUEST_FAILED;

        my $data = $obj->{data} || {};
        my $timestamp = $obj->{timestamp};
        my $checksum = delete $obj->{checksum};

        unless ($request) {
            $err = $NO_REQUEST;
            error($err);
        }

	if ($request =~ /^_/) {
	    # assumed to be a private method
	    $err = $UNKNOWN_METHOD;
	    error($err);
	}

        unless (defined $timestamp) {
            $err = $NO_TIMESTAMP;
            error($err);
        }

        unless ($checksum) {
            $err = $NO_CHECKSUM;
            error($err);
        }

        unless ($timestamp =~ /^\d+$/) {
            $err = $BAD_TIMESTAMP;
            error($err);
        }

        if ((my $timediff = abs($timestamp - time())) > 30) {
            $err = $TIME_MISMATCH;
            error($err);
        }

#       if ($checksum ne md5_hex(objToJson($obj))) {
#           $err = $CHECKSUM_MISMATCH;
#           error($err);
#       }

        if ($handler->can($request)) {
            $res = $handler->$request($data);
        } elsif (my $map = $ForwardMap{$request}) {
            my $forward = {
                action => $map->{action},
                host => $map->{host},
                ssl => $map->{ssl},
                xml => $map->{xml},
                username => $map->{username},
                password => $map->{password},
                data => $data,
            }; 

            say("Forwarding `$request' to `$map->{host}' automatically");

            $res = $handler->forward($forward);
        } else {
            $err = $UNKNOWN_METHOD;
            error($err);
        }

        $err = $NO_ERROR;
    };

    if (my $error = $@) {
	chomp $error;
	$error =~ s/\s+$//g;

        if ($error =~ /Can't locate object method "([^"]+)" via package "([^"]+)"/) {
            $err = $UNKNOWN_METHOD;
            #$@ = "Uknown method '$2::$1'";
            $error = 'Uknown method';
        }

	if ($err != $REQUEST_FAILED) {
	    $error =~ s/\s*\bat\b.+//;
	} 

	$@ = $error;
    }

    say("`$request' from $ip return code $err\n");

    return encode({
        err => int($err),
        errmsg => $@,
        res => $res
    }, $use_xml);
}
