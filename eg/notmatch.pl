#!/usr/bin/perl -w
use strict;
use Getopt::Long;
use Regexp::Log::BlueCoat;

my %CONF;

GetOptions( \%CONF, 'format=s', 'ufs=s', 'login=s' )
  or die
"Usage: notmatch.pl -format <formatstring> -ufs <ufs> -login <login-type> file";

die "The format argument is mandatory" unless exists $CONF{format};

my $log = Regexp::Log::BlueCoat->new(
    format  => $CONF{format},
    ufs     => $CONF{ufs},
    login   => $CONF{login},
    capture => [':all'],
);

my @fields = $log->capture;
my $re     = $log->regexp;

print << "EOT";
# This file was generated by notmatch.pl with options:
#     format = $CONF{format}
#     ufs    = @{[ $CONF{ufs}   ||'' ]}
#     login  = @{[ $CONF{login} || '' ]}
#
# Regexp::Log::BlueCoat version $Regexp::Log::BlueCoat::VERSION generated the following regexp:
#    $re
#
# Captured fields: @fields
#
EOT

while (<>) {
    next if /^(?:Windows_Media|<RealMedia>)/;
    my %data;
    @data{@fields} = (m/$re/og) or print;
    print "\n#\n";
}
