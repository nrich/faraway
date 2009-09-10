#!/usr/bin/perl 

package Faraway::Handler;

use strict;
use warnings;

use Faraway::Client;
use POSIX qw//;

sub new {
    my ($package, %opts) = @_;

    $package = ref $package || $package;

    return bless {
	logger => $opts{Logger},
    }, $package;
}

sub _log {
    my ($self, $line) = @_;

    my (undef, undef, undef, $subname) = caller(1);

    $line = "$subname -> $line";

    if ($self->{logger}) {
	$self->{logger}->($line);
    } else {
	chomp $line;

	my $ts = POSIX::strftime '%Y-%m-%d %H:%M:%S', localtime();

	my $out = "$ts [$$] $line\n";

	print STDERR $out;
    }
}

sub echotest {
    my ($self, $args) = @_;

    return $args;
}

sub systime {
    my ($self, $args) = @_;

    return {time => time()};
}

sub uptime {
    my ($self, $args) = @_;

    open my $fh, '<', '/proc/uptime' or die "Could not open /proc/uptime: $!\n";
    my $line = <$fh>;
    $fh->close();

    my ($uptime, $idle) = split(/\s+/, $line);

    return {uptime => $uptime, idle => $idle};
}

sub methods {
    my ($self, $args) = @_;

    my @methods = ();

    no strict 'refs';

    my $class = ref $self;

    my @classes = ($class);
    unshift @classes, @{"${class}::ISA"};

    foreach my $classname (@classes) {
	my %methods = %{"${classname}::"};

	foreach my $methodname (keys %methods) { 
	    push @methods, "${methodname}" if $self->_method_list_ok($methodname) and $classname eq $class;
	}
    }

    use strict 'refs';

    return [sort @methods];
}

sub error {
    my ($self, $args) = @_;

    die $args->{msg} || $@;

    return {};
}

sub forward {
    my ($self, $args) = @_;

    my $host = $args->{host};
    my $action = $args->{action};

    die 'No host to forward to' unless $host;
    die 'No action set' unless $action;
    die 'Cannot call forward from forward' if $action eq 'forward';

    my $data = $args->{data}||{};
    my $port = $args->{port};
    my $ssl = $args->{ssl};
    my $xml = $args->{xml};
    my $username = $args->{username};
    my $password = $args->{password};

    my $remote = Faraway::Client->new(
	Host => $host,
	Port => $port,
	SSL => $ssl,
	XML => $xml,
	Username => $username,
	Password => $password,
    );

    $self->_log("Forwarding action `$action' to host `$host'");

    my $res = $remote->$action($data);

    if ($res->{err}) {
	die $res->{errmsg};
    }

    return $res->{res};
}

sub _format_time {
    my ($self, $time) = @_;

    my @formatted = ();

    my %formatting = (
	86400 => 'day',
	3600 => 'hour',
	60 => 'minute',
	1 => 'second',
    );

    foreach my $inverval (reverse sort {$a <=> $b} keys %formatting) {
	if ($time >= $inverval) {
	    my $passed = int($time/$inverval);
	    $time = $time - ($passed * $inverval);

	    push @formatted, $passed == 1 ? "$passed $formatting{$inverval}" : "$passed $formatting{$inverval}s";
	}
    }

    return join(', ', @formatted); 
}

sub _format_data {
    my ($self, $data) = @_;

    my @formatted = ();

    my %formatting = (
	1_000_000_000 => 'GB',
	1_000_000 => 'MB',
	1_000 => 'KB',
	1 => 'B',
    );

    my $amount = '0 Bs';
    foreach my $d (reverse sort {$a <=> $b} keys %formatting) {
	if ($data >= $d) {
	    $amount = sprintf '%.02f', ($data/$d);

	    $amount = "$amount $formatting{$d}s";
	    last;
	}
    }

    return $amount; 
}

sub _format_datarates {
    my ($self, $data) = @_;

    my @formatted = ();

    my %formatting = (
	1_000_000_000 => 'Gbps',
	1_000_000 => 'Mbps',
	1_000 => 'Kbps',
	1 => 'bps',
    );

    my $amount = '0 Bs';
    foreach my $d (reverse sort {$a <=> $b} keys %formatting) {
	if ($data >= $d) {
	    $amount = sprintf '%.02f', ($data/$d);

	    $amount = "$amount $formatting{$d}";
	    last;
	}
    }

    return $amount; 
}


sub _method_list_ok {
    my ($self, $methodname) = @_;

    return 0 if $methodname =~ /^_/;
    return 0 unless $self->can($methodname);

    return 0 if {
        new => 1,
        can => 1,
        isa => 1,
	VERSION => 1,
    }->{$methodname};

    return 1;
}

sub _valid_mac {
    my ($self, $mac) = @_;

    return $mac =~ /^[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}\:[0-9A-F]{2}$/i;
}

sub _valid_ip { 
    my ($self, $ip) = @_; 
 
    return 0 unless (my @octets = $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/g); 
     
    foreach (@octets) { 
        return 0 if $_ < 0 or $_ > 255; 
    } 
 
    return 1; 
}


1;
