use Test::More tests => 5;
use strict;
use Regexp::Log::BlueCoat;

my ( $log, $regexp );

# default value
is( $Regexp::Log::BlueCoat::UFS{smartfilter}{hm},
    'humor', "Default for category" );

# instance method
$log = Regexp::Log::BlueCoat->new( ufs => 'smartfilter', format => '%f' );
$log->ufs_category( hm => 'Fun' );
$regexp = $log->regexp;

like( $regexp, qr/\bFun\b/, "ufs_category on instance" );
is( $Regexp::Log::BlueCoat::UFS{smartfilter}{hm},
    'humor', "Class data not changed" );

# class method
undef $log;
Regexp::Log::BlueCoat->ufs_category( 'smartfilter', js => 'Work' );

$log = Regexp::Log::BlueCoat->new( ufs => 'smartfilter', format => '%f' );
$regexp = $log->regexp;

like( $regexp, qr/\bWork\b/, "ufs_category from class" );
is( $Regexp::Log::BlueCoat::UFS{smartfilter}{js}, 'Work',
    "Class data changed" );

