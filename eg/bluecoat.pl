#!/usr/bin/perl -w
use strict;
use Regexp::Log::BlueCoat;

my $log = Regexp::Log::BlueCoat->new(
    format  => '%g %e %a %w/%s %b %m %i %u %H/%d %c %f %A',
    capture => [ ':all' ],
    ufs     => 'smartfilter',
    login   => 'ldap',
);

$\ = $/;
print $log->format;
print $log->regexp;
print join ' ', $log->capture;
print '';
print join ' ', $log->fields;
