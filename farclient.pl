#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Std qw/getopts/;
use Faraway::Client;

my %opts = ();
getopts('h:p:sxu:a:', \%opts);

my ($action, @args) = @ARGV;

my $data = {};

while (@args) {
    my $key = shift @args;
    my $val = shift @args;

    if (defined $data->{$key}) {
	if (ref $data->{$key} eq 'ARRAY') {
	    push @{$data->{$key}}, $val;
	} else {
	    my $existing = $data->{$key};
	    $data->{$key} = [$existing, $val];
	}
    } else {
	$data->{$key} = $val;
    }
}

my $client = Faraway::Client->new(
    Host => $opts{h}, 
    Port => $opts{p}, 
    SSL => $opts{s}, 
    XML => $opts{x}, 
    Username => $opts{u}, 
    Password => $opts{a}
);

my $result = $client->$action($data);

require Data::Dumper;
print STDERR Data::Dumper::Dumper($result);
