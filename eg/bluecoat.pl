#!/usr/bin/perl -w
use strict;
use Regexp::Log::BlueCoat;

my $log = Regexp::Log::BlueCoat->new(
    format  => '%g %e %w/%s %m %%H/%d %f %A',
    capture => [qw(c-ip)],
    ufs     => 'smartfilter',
);

my $re = $log->regexp;

print ref $re, $/, $re, $/;

