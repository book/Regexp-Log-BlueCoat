use Test::More tests => 5;
use strict;
use Regexp::Log::BlueCoat;

my $log = Regexp::Log::BlueCoat->new();

# Object type
is( ref($log), 'Regexp::Log::BlueCoat', "Object type" );

# check the defaults
is( $log->format, '', "Default format" );
is( $log->ufs,    '', "Default ufs" );
is( $log->login,  '', "Default login" );

# check the accessors
$log->ufs('smartfilter');
is( $log->ufs, 'smartfilter', "ufs()" );
