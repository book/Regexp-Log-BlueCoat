use Test::More tests => 5;
use strict;
use Regexp::Log::BlueCoat;

my $log = Regexp::Log::BlueCoat->new();

# Object type
ok( ref($log) eq 'Regexp::Log::BlueCoat', "Object type" );

# check the defaults
ok( $log->format eq '', "Default format" );
ok( $log->ufs    eq '', "Default ufs" );
ok( $log->login  eq '', "Default login" );

# check the accessors
$log->ufs('smartfilter');
ok( $log->ufs eq 'smartfilter', "ufs()" );
