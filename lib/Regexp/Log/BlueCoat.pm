package Regexp::Log::BlueCoat;

use strict;
use base qw( Regexp::Log );
use vars qw( $VERSION %DEFAULT %FORMAT %REGEXP );

$VERSION = 0.01;

%DEFAULT = (
    format  => '',
    capture => [],
    ufs     => '',
);

%FORMAT = (
    ':squid' => '%g %e %a %w/%s %b %m %i %u %H/%d %c',
    ':clf'   => '%h %l %u %t "%r" %s %b',
    ':elf'   => '%h %l %u %L "%r" %s %b "%R" "%A"',
    ':iis'   => '%a, -, %x, %y, %S, %N, %I, %e, %b, %B, %s, 0, %m, %U, -',
);

# define the BlueCoat specific stuff
%REGEXP = (

#%g %e %a %w/%s %b %m %i %u %H/%d %c %f %A
    # %% - Denotes '%' character -
    '%%' => '%',

    # %a   c-ip Client IP address. Yes
    '%a' => '(?#c-ip)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?#!c-ip)',
    # %b   sc-bytes Number of bytes returned by the server (or the Cache).  Yes
    '%b' => '(?#sc-bytes)\d+(?#!sc-bytes)',
    # %c   cs (content-type) The type of object. Usually the MIME-type. No
    '%c' => '(?#cs-content-type)-|UNKNOWN|\\S+/\\S+(?#!cs-content-type)',
    # %d   cs-supplier-name SUPPLIER NAME - Name or IP address of the server/cache from which the object was received.  Yes
    '%d' => '(?#cs-supplier-name)(?:\d+\.|[-\w]+\.)+(?#!cs-supplier-name)',
    # %e   time-taken Number of milliseconds request took to process.  Yes
    '%e' => '(?#time-taken)\\d+(?#!time-taken)',

    # %f   sc-filter-category Filtering reason. Why it was denied (such as sex or business) No
    # TODO check in which Perl version (?{}) appears
    '%f' => '(?{croak "You must define \'ufs\' to use %f in format"})',

    # %g    timestamp UNIX type timestamp. Yes
    '%g' => '(?#timestamp)\d+\.\d+(?#!timestamp)',

    # %h    c-ip Client Hostname (uses IP to avoid reverse DNS) - same as %a Yes
    '%h' => '(?#c-hostname)(?:\d+\.|[-\w+]\.)+(?#!c-hostname)',

    # %i    cs-uri The requested URI. Note: Web trends expects this to be only cs-uri-stem + cs-uri-query No
    '%i' => '(?#cs-uri)\\S+://\\S+(?#!cs-uri)',
    # %j    -  [Not used.] -
    '%j' => '',

    # %l    - Client Identification string. (User Login name remote). - always '-' Yes
    # %m    cs-method HTTP method. HTTP methods include GET, PUT, POST, and so on.  Yes
    '%m' => '(?#cs-method)-|OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT(?#!cs-method)',

    # %n    - [Not used.] -
    '%n' => '',

    # %o    - [Not used.] -
    '%o' => '',

    # %p    r-port Port fetched from on host - origin server port Yes
    '%p' => '(?#r-port)\\d+(?#!r-port)',

    # %q    - [Not used.] -
    '%q' => '',

    # %r    cs-request-line First line of the request No
    # %s    sc-status The code returned by the cache to the client (HTTP code).  Yes
    '%s' => '(?#sc-status)\\d\\d\\d(?#!sc-status)',

    # %t    gmttime GMT date and time of the user request, in the format [DD/MM/YYYY:hh:mm:ss GMT] Yes
    '%t' =>
'\\[(?#gmttime)(?#day)\\d\\d(?#!day)/(?#month)\\d\\d(?#!month)/(?#year)\\d\\d\\d\\d(?#!year):(?#hour)\\d\\d(?#!hour):(?#minute)(?#!minute):(?#second)(?#!second) GMT(?#!gmttime)\\]',

    # %u    cs-username Authenticated user ID. Yes
    '%u' => '(?{croak "You must define \'login\' to use %u in format"})',
    # %v    cs-host Name of host sourcing the object. Yes
    # %w    s-action What type of action did the CM take to process this request. NOTE: 'cached' is used by ELFF but has int value.  Yes
    '%w' =>
'(?#s-action)(?:TCP_(?:CLIENT_REFRESH|DENIED|ERR_MISS|HIT|M(?:EM_HIT|ISS)|NC_MISS|PARTIAL_MISS|REFRESH_(?:HIT|MISS)|S(?:PLASHED|WAPFAIL)|TUNNELED)?|UDP_(?:DENIED|HIT|INVALID|MISS(?:_NOFETCH)?)?)(?#!s-action)',

    # %x    date Date in YYYY-MM-DD format Yes
    # %y    time GMT time in HH:MM:SS format No
    # %z    - [Not used.] -
    '%z' => '',

    # %A    cs (user-agent) User agent No
    '%A' => '(?#user-agent).*?(?#!user-agent)',

    # %B    cs-bytes The number of bytes received by the server Yes
    # %C    cs (cookie) Cookie data No
    # %D    s-supplier-ip SUPPLIER IP - IP address of server/cache from which the object was received.  Yes
    # %E    s-Policy-Message Policy enforcement message Yes
    # %F    - [Not used.] -
    '%F' => '',

    # %G    - [Not used.] -
    '%G' => '',

    # %H    s-hierarchy How and where the object was retrieved from the cache hierarchy (DIRECT from the server, PARENT_HIT = from the parent cache, and so on) No
    '%H' => '(?#s-hierarchy)DIRECT|NONE|(?:PARENT|SIBLING)_HIT|FIRST_PARENT_MISS(?#!s-hierarchy)',

    # %I    s-ip Server IP, the IP address of the server on which the log entry was generated Yes
    # %J    - [Not used.] -
    '%J' => '',

    # %K    - [Not used.] -
    '%K' => '',

    # %L    localtime Local date and time of the user request in format: [DD/MMM/YYYY:hh:mm:ss +nnnn] Yes
    '%L' =>
'\\[(?#localtime)(?#day)\\d\\d(?#!day)/(?#month)\\d\\d(?#!month)/(?#year)\\d\\d\\d\\d(?#!year):(?#hour)\\d\\d(?#!hour):(?#minute)(?#!minute):(?#second)(?#!second) \\+\\d\\d\\d\\d(?#!localtime)\\]',

    # %M    - [Not used.] -
    '%M' => '',

    # %N    s-computername Server name, the name of the server on which the log entry was generated Yes
    '%N' => '(?#s-computername)\\w+(?#!s-computername)',

    # %O    - [Not used.] -
    '%O' => '',

    # %P    s-port Server port, the port number the client is connected to.  Yes
    # %Q    cs-uri-query The URI query portion of the URL No
    # %R    cs (Referer) Request referrer No
    # %S    s-sitename Internet service and instance number running on client computer Yes
    # %T    duration Elapsed time, seconds Yes
    '%T' => '(?#duration)\\d+(?#!duration)',

    # %U    cs-uri-stem Object path from request URL Yes
    # %V    cs-version The protocol (HTTP, FTP) version used by the client.  Yes
    # %W    sc-filter-result UFS event (May differ between Websense or SmartFilter or others).  No
    '%W' => '(?{croak "You must define \'ufs\' to use %W in format"})',

    # %X    cs (X-Forwarded-For) The IP address of the device which sent the HTTP request.  No
# %Y    - [Not used.] -
    '%Y' => '',

    # %Z    - [Not used.] -
    '%Z' => '',

    # UFS specific
    # Smartfilter
    '%f-smartfilter' =>
'(?#sc-filter-category)-|uncategorized|content_filter_not_applied|Anonymizer/Translator|Art/Culture|Chat|Criminal_Skills|Cults/Occult|Dating|Drugs|Entertainment|Obscene/Extreme|Gambling|Games|General_News|Hate_Speech|Humor|Investing|Job_Search|Lifestyle|Mature|MP3_Sites|Nudity|Online_Sales|Personal|Politics/Religion|Portal_Sites|Self_Help/Health|Sex|Sports|Travel|Usenet_News|Webmail(?#!sc-filter-category)',
    '%W-smartfilter' => '\w+',    # TODO find something better

    # Login specific
    '%u-username' => '(?#cs-username)[-.\w]+(?#!cs-username)',
    '%u-ldap'     => '(?#cs-username)-|(?:[A-Za-z]=[^,]*,?)+(?#!cs-username)',
);

=pod
 
    source    => '([\\d.]+|[\\w.]+)',
    code      => '\\w+/(\\d+)',
    size      => '(\\d+)',
    method    => '(-|OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)',
    url       => '(\\S+://\\S+)',
    ldap      => '(-|(?:(?:CN|OU|O)=[^,]*,?)+)',
    direct    => '\\w+/(?:-|\\S+)',
    mime      => '(-|UNKNOWN|\\S+/\\S+)',
    category  =>
'(-|uncategorized|content_filter_not_applied|Anonymizer/Translator|Art/Culture|Chat|Criminal_Skills|Cults/Occult|Dating|Drugs|Entertainment|Obscene/Extreme|Gambling|Games|General_News|Hate_Speech|Humor|Investing|Job_Search|Lifestyle|Mature|MP3_Sites|Nudity|Online_Sales|Personal|Politics/Religion|Portal_Sites|Self_Help/Health|Sex|Sports|Travel|Usenet_News|Webmail)',
    useragent => '(-|.*?)',
=cut

sub _preprocess {
    my $self = shift;
    my ( $ufs, $login ) = ( $self->{ufs}, $self->{login} );

    # UFS specific regexps
    $self->{_regexp} =~ s/%([fW])/%$1-$ufs/g
      if $ufs        =~ /^(?:smartfilter|websense)$/;

    # Login specific regexps
    $self->{_regexp} =~ s/%u/%u-$login/g
      if $login      =~ /^(?:ldap|username)$/;

    # Multiple consecutive spaces are compressed to a single space
    $self->{_regexp} =~ s/ +/ /g;
}

=head1 NAME

Regexp::Log::BlueCoat - A regexp builder to parse BlueCoat log files

=head1 SYNOPSIS

    my $blue = Regexp::Log::BlueCoat->new(
        format  => '%g %e %a %w/%s %b %m %i %u %H/%d %c',
        capture => [qw( host code )],
    );

    # the format() and capture() methods can be used to set or get
    $blue->format('%g %e %a %w/%s %b %m %i %u %H/%d %c %f %A');
    $blue->capture(qw( host code ));
    $blue->ufs( 'smartfilter' );

    # this is necessary to know in which order
    # we will receive the captured fields from the regex
    my @fields = $blue->capture;

    # the all-powerful capturing regex :-)
    my $re = $blue->regex;

    while (<>) {
        my %data;
        @data{@fields} = /$re/;

        # do something with the fields
    }

=head1 DESCRIPTION

=head2 Methods

See the Regexp::Log for a description of the standard Regexp::Log::*
interface.

Regexp::Log::BlueCoat's constructor accepts several BlueCoat specific
arguments:

    ufs    - URL Filtering Service

Note: Though BlueCoat supports SmartFilter, Websense and others,
Regexp::Log::BlueCoat only support I<SmartFilter> UFS in this version.

The appropriate accessors are defined for them (if used to set, they
return the previous value for the attribute).

=cut

sub ufs {
    my $self = shift;
    my $ufs  = $self->{ufs};
    $self->{ufs} = shift if @_;
    return $ufs;
}

=head2 ## Please see file perltidy.ERR
Predefined formats

Squid log format: C<%g %e %a %w/%s %b %m %i %u %H/%d %c>
NCSA common log format: C<%h %l %u %t "%r" %s %b>
NCSA extended log format: C<%h %l %u %L "%r" %s %b "%R" "%A">
Microsoft IIS format: C<%a, -, %x, %y, %S, %N, %I, %e, %b, %B, %s, 0, %m, %U, ->

=head1 FIELDS

=head2 Blue Coat custom format

(This is from Blue Coat's documentation.)

space character N/A Multiple consecutive spaces are compressed to a single space Yes

 Name ELFF
 ------------------------------------------------------------------------
 %    -          Denotes an expansion field -
 %%   -          Denotes '%' character -
 %a   c-ip Client IP address. Yes
 %b   sc-bytes Number of bytes returned by the server (or the Cache).  Yes
 %c   cs (content-type) The type of object. Usually the MIME-type. No
 %d   cs-supplier-name SUPPLIER NAME - Name or IP address of the server/cache from which the object was received.  Yes
 %e   time-taken Number of milliseconds request took to process.  Yes
 %f   sc-filter-category Filtering reason. Why it was denied (such as sex or business) No
 %g    timestamp UNIX type timestamp. Yes
 %h    c-ip Client Hostname (uses IP to avoid reverse DNS) - same as %a Yes
 %i    cs-uri The requested URI. Note: Web trends expects this to be only cs-uri-stem + cs-uri-query No
 %j    -  [Not used.] -
 %l    - Client Identification string. (User Login name remote). - always '-' Yes
 %m    cs-method HTTP method. HTTP methods include GET, PUT, POST, and so on.  Yes
 %n    - [Not used.] -
 %o    - [Not used.] -
 %p    r-port Port fetched from on host - origin server port Yes
 %q    - [Not used.] -
 %r    cs-request-line First line of the request No
 %s    sc-status The code returned by the cache to the client (HTTP code).  Yes
 %t    gmttime GMT date and time of the user request, in the format [DD/MM/YYYY:hh:mm:ss GMT] Yes
 %u    cs-username Authenticated user ID. Yes
 %v    cs-host Name of host sourcing the object. Yes
 %w    s-action What type of action did the CM take to process this request. NOTE: 'cached' is used by ELFF but has int value.  Yes
 %x    date Date in YYYY-MM-DD format Yes
 %y    time GMT time in HH:MM:SS format No
 %z    - [Not used.] -
 %A    cs (user-agent) User agent No
 %B    cs-bytes The number of bytes received by the server Yes
 %C    cs (cookie) Cookie data No
 %D    s-supplier-ip SUPPLIER IP - IP address of server/cache from which the object was received.  Yes
 %E    s-Policy-Message Policy enforcement message Yes
 %F    - [Not used.] -
 %G    - [Not used.] -
 %H    s-hierarchy How and where the object was retrieved from the cache hierarchy (DIRECT from the server, PARENT_HIT = from the parent cache, and so on) No
 %I    s-ip Server IP, the IP address of the server on which the log entry was generated Yes
 %J    - [Not used.] -
 %K    - [Not used.] -
 %L    localtime Local date and time of the user request in format: [DD/MMM/YYYY:hh:mm:ss +nnnn] Yes
 %M    - [Not used.] -
 %N    s-computername Server name, the name of the server on which the log entry was generated Yes
 %O    - [Not used.] -
 %P    s-port Server port, the port number the client is connected to.  Yes
 %Q    cs-uri-query The URI query portion of the URL No
 %R    cs (Referer) Request referrer No
 %S    s-sitename Internet service and instance number running on client computer Yes
 %T    duration Elapsed time, seconds Yes
 %U    cs-uri-stem Object path from request URL Yes
 %V    cs-version The protocol (HTTP, FTP) version used by the client.  Yes
 %W    sc-filter-result UFS event (May differ between Websense or SmartFilter or others).  No
 %X    cs (X-Forwarded-For) The IP address of the device which sent the HTTP request.  No
 %Y    - [Not used.] -
 %Z    - [Not used.] -
 
Example Access Log Formats

=head1 TODO

Support BlueCoat's standard formats: NCSA common log format,
Squid-compatible format, WC3 Extended Log File Format, custom.

=head1 REFERENCES

Blue Coat Systems Port 80 Security Appliance, I<Configuration and Management
Guide>: http://www.bluecoat.com/downloads/manuals/BC_Config_Mgmt_Guide.pdf

=head1 THANKS

Thanks to Jarkko Hietaniemi for Regex::PreSuf.

=head1 AUTHOR

Philippe 'BooK' Bruhat E<lt>book@cpan.orgE<gt>.

=cut

1;
