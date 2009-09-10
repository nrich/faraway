#!/usr/bin/perl -w

package Faraway::Client;

use strict;

use LWP::UserAgent;
use JSON;
use XML::Simple;
use Digest::MD5 qw/md5_hex/;
use vars qw/$AUTOLOAD/;

sub new {
    my ($package, %args) = @_;

    $package = ref $package || $package;

    my $default_port = $args{SSL} ? 9096 : 9095;

    return bless {
	host => $args{Host}||'127.0.0.1',
	port => $args{Port}||$default_port,
        username => $args{Username}||'',
        password => $args{Password}||'',
	die_on_error => $args{DieOnError}||0,
	simple_return => $args{DieOnError}||$args{SimpleReturn}||0,
	ssl => $args{SSL}||0,
	xml => $args{XML}||0,
    };
}

sub _connect {
    my ($self) = @_;

    # TODO this conflicts with WWW:Mechanize...
    #return $self->{http} if $self->{http}; 

    my $http = LWP::UserAgent->new(
	keep_alive => 1,
    );

    if ($self->{username} and $self->{password}) {
        $http->credentials("$self->{host}:$self->{port}", 'Faraway', $self->{username}, $self->{password});
    }

    $self->{http} = $http;
}

sub call_faraway {
    my ($self, $action, $args) = @_;

    my $http = $self->_connect();

    my $host = $self->{host};
    my $port = $self->{port};

    my $transport = $self->{ssl} ? 'https' : 'http';

    my $url = "$transport://$host:$port/$action";

    my $obj = {
	timestamp => time(), 
	data => $args
    };

    my $md5 = md5_hex(to_json($obj));
    $obj->{checksum} = $md5;

    my $res = $http->post($url, 'Content' => $self->{xml} ? XMLout($obj) : to_json($obj));

    my $response;
    if ($res->is_success()) {
	$response = $self->{xml} ? XMLin($res->content()) : from_json($res->content());
    } else {
	$response = {err => 100, errmsg => $res->status_line()};
    }

    die "Error calling $action\@$self->{host}: $response->{err} - $response->{errmsg}" 
	if $response->{err} and $self->{die_on_error};

    return $self->{simple_return} ? $response->{res} : $response;
}

sub AUTOLOAD {
    my $self = shift;

    return undef unless ref $self;

    (my $method = $AUTOLOAD) =~ s/.*:://;

    return $self->call_faraway($method, @_);
}

sub DESTROY {
    my $self = shift;
}

1;
