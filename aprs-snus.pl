#! /usr/bin/perl
# note, you'll still need to set the permission to 755 if you want
# to run this from the command line
# you should be able to pipe the output to a file and run this in the background

use warnings;
use strict;

# all the various CPAN modules you'll need to verify
# are installed before this script will run
use Ham::APRS::IS;
use Ham::APRS::FAP qw(parseaprs);

#use Data::Dumper;
use POSIX qw(strftime);
use Digest::SHA qw(sha256 sha256_hex);
use MIME::Base64 qw(encode_base64);
use JSON;
use LWP::UserAgent;
use HTTP::Request::Common;
use Digest::CRC qw(crc64 crc32 crc16 crcccitt crc crc8 crcopenpgparmor);

# this defined the control-c handler so that
# we close out all the interfaces on forced exit
$SIG{INT} = \&outofhere;

# define some local variables
my ( $callsign, $srccallsign, $filter, $sequence, $mytime, $mydate, $myftime, $my3339time, $lat, $lon, $alt, $sats, $temperature, $vbatt, $vsolar );
my ( $_id, $_raw, $_sentence, $server_endpoint, $passcode );

# set to 1 to enable debugging output
my $debug = 0;

# define some globals for configuration
$callsign = "NOCALL";

# the APRS-IS passcode
$passcode = -1;

# the APRS-IS filter string
$filter = "b/<buddy list>";

#the uri of the habitat couchdb
$server_endpoint = "http://habitat.habhub.org/habitat";

# connect to IS server with filtering for whichever callsign
my $is = new Ham::APRS::IS( 'rotate.aprs.net:14580', $callsign, 'passcode' => int($passcode),
    'appid' => 'IS-pm-test 1.0', 'filter' => $filter );
$is->connect( 'retryuntil' => 3 ) || die "Failed to connect: $is->{error}";

#loop forever
while (1) {

    # get the IS data if not a comment line
    my $l = $is->getline_noncomment();
    next if ( !defined $l );

    #initialize some time variables that are used below
    $mydate = strftime "%y%m%d", gmtime;
    $mytime = strftime "%H%M%S", gmtime;

    #$myftime = strftime "%H:%M:%S", gmtime;
    $my3339time = strftime "%Y-%m-%dT%T%z", gmtime;
    $my3339time =~ s/..$/:$&/;

    if ($debug) {
        print "\n--- new packet ---\n$l\n";
    }

    # parse the aprs data back to a hash structure in perl, decoding all the elements
    my %packetdata;
    my $retval = parseaprs( $l, \%packetdata );

    #if the parse was successful
    if ( $retval == 1 ) {

        # just for debugging dump out the aprs hash
        if ($debug) {
            while ( my ( $key, $value ) = each(%packetdata) ) {
                print "$key: $value\n";
            }
            if ( exists( $packetdata{'telemetry'} ) ) {
                print "Got Telem\n";
                while ( my ( $key1, $value1 ) = each( $packetdata{'telemetry'} ) ) {
                    print "$key1: $value1\n";
                }
                if ( exists( $packetdata{'telemetry'}{'vals'} ) ) {
                    print "Got Telem Vals\n";
                    for my $i ( 0 .. $#{ $packetdata{'telemetry'}{'vals'} } ) {
                        print "$packetdata{'telemetry'}->{'vals'}[$i]\n";
                    }
                }
            }
        }

        # sample strings in UKHAS format
        # $$B-55,193,223308,140607,56.1620,3.0036,9892,6,-44,3.67,0*6559\n
        # $$W7QO,353,200705,140412,34.0848,-83.9476,346,9,30,1.29,1.13*001C\n

        # put common used elements into easy to use variables
        # NOTE the telmetry->vals->array as unique to each UserAgent
        # they are dependant on the order they are placed in the aprs
        # telemetry and there are no name associations available once decoded
        # so you'll need to adjust those to mate the correct array element
        # with the correct UKHAS element
        #$srccallsign = $packetdata{'srccallsign'};
        $sequence = $packetdata{'telemetry'}{'seq'};
        $lat      = $packetdata{'latitude'};

        #$lat = 34.10;
        $lon = $packetdata{'longitude'};

        #$lon = -83.90;
        $sats = $packetdata{'telemetry'}{'vals'}[3];
        $alt  = $packetdata{'altitude'};
        $temperature = ( ( $packetdata{'telemetry'}{'vals'}[2] * 0.1 ) - 273.2 );
        $vbatt  = ( $packetdata{'telemetry'}{'vals'}[0] * 0.001 );
        $vsolar = ( $packetdata{'telemetry'}{'vals'}[1] * 0.001 );

        # build up the first part of the UKHAS format
        # NOTE: this format is defined when you actually create a payload document on the habhub.org site
        # so it will need to be adjusted to reflect any ordering, numbers, types, etc of values
        # you can change $callsign to $srccallsign and uncomment it above, if you do the string will
        # come from the aprs data
        my $str1 = sprintf( "$callsign,$sequence,$mytime,$mydate,%.4f,%.4f,%4.0f,$sats,%2.0f,%1.2f,%1.2f",
            $lat, $lon, $alt, $temperature, $vbatt, $vsolar );

        # add the $$'s and the final CRC
        $_sentence = sprintf( "\$\$%s*%04X\n", $str1, crcccitt($str1) );
        if ($debug) {
            print "\n$_sentence\n";
        }

        # generate the base64 version of the _sentence string
        # be default the encode_base64 routine wants to add an CR/LF at position 76
        # you send it an empty string as the second parameter to disable that
        $_raw = encode_base64( $_sentence, "" );
        if ($debug) {
            print "$_raw\n";
        }

        # generate the sha256 encoded _raw string
        $_id = sha256_hex($_raw);
        if ($debug) {
            print "\n$_id\n\n";
        }

        # build the perl structure to be used to encode the json
        # at first I thought I needed to decode everything, but in talking with Adam Grieg
        # he told me that no, the server does that
        # i left the decode in here just incase that every changes
        # NOTE the Reciever will show as APRS_callsign
        my $data = { _id => $_id,
            type => "payload_telemetry",
            data => {

                #battery=>$vbatt,
                #time=>$myftime,
                #_sentence=>$_sentence,
                #satellites=>int($sats),
                #sentence_id=>int($sequence),
                #_protocol=>"UKHAS",
                #date=>$mydate,
                #payload=>$callsign,
                #altitude=>int($alt),
                #latitude=>$lat,
                #longitude=>$lon,
                #temperature_internal=>$temperature,
                _raw => $_raw

                    #solar_panel=>$vsolar,
                    #_parsed=>{time_parsed=>$my3339time,
                    #					 configuration_sentence_index=>0,
                    #					 payload_configuration=>$payload_doc_id
                    #					},
            },
            receivers => { 'APRS_' . $callsign => { time_created => $my3339time,
                    time_uploaded => $my3339time
                    }
                }
        };

        # create the json object and encode the above perl structure
        my $json      = JSON->new;
        my $post_json = $json->encode($data);
        if ($debug) {
            print "$post_json\n";
        }

        # create the HTTP interface and push the json to the
        # couchdb server
        # return an error if not successful
        my $ua = LWP::UserAgent->new;
        my $req = HTTP::Request->new( POST => $server_endpoint );
        $req->header( 'Content-Type' => 'application/json' );
        $req->content($post_json);

        # do that actual HTTP request for POST
        my $resp = $ua->request($req);

        if ( $resp->is_success ) {
            if ($debug) {
                print "\n" . $resp->decoded_content;
            }
        } else {
            print "$resp->code\n";
            print "$resp->message\n";
        }

    } else {
        warn "Parsing failed: $packetdata{resultmsg} ($packetdata{resultcode})\n";
    }
}

$is->disconnect() || die "Failed to disconnect: $is->{error}";
exit 0;

# on control - c what to do when issued
sub outofhere
{
    $SIG{INT} = \&outofhere;
    $is->disconnect() || die "Failed to disconnect: $is->{error}";
    exit 0;
}

