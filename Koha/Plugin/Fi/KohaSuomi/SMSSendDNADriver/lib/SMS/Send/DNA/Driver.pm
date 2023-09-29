package SMS::Send::DNA::Driver;
#use Modern::Perl; #Can't use this since SMS::Send uses hash keys starting with _
use utf8;
use SMS::Send::Driver ();
use Mojo::UserAgent;
use MIME::Base64;
use URI::Escape;
use Encode;
use Mojo::JSON qw(from_json);
use Mojo::URL;
use POSIX;
use UUID;

use Try::Tiny;

use vars qw{$VERSION @ISA};
BEGIN {
        $VERSION = '0.01';
        @ISA     = 'SMS::Send::Driver';
}


#####################################################################
# Constructor

sub new {
        my $class = shift;
        my $params = {@_};

        my $username = $params->{_login} ? $params->{_login} : $params->{_user};
        my $password = $params->{_password} ? $params->{_password} : $params->{_passwd};
        my $appId = $params->{_appId};
        my $baseUrl = $params->{_baseUrl};
        my $callbackUrl = $params->{_callbackUrl};

        if (! defined $username ) {
            warn "->send_sms(_login) must be defined!";
            return;
        }
        if (! defined $password ) {
            warn "->send_sms(_password) must be defined!";
            return;
        }

        if (! defined $appId ) {
            warn "->send_sms(_appId) must be defined!";
            return;
        }

        if (! defined $baseUrl ) {
            warn "->send_sms(_baseUrl) must be defined!";
            return;
        }

        #Prevent injection attack
        $self->{_login} =~ s/'//g;
        $self->{_password} =~ s/'//g;

        # Create the object
        my $self = bless {}, $class;

        $self->{_login} = $username;
        $self->{_password} = $password;
        $self->{_appId} = $appId;
        $self->{_baseUrl} = $baseUrl;
        $self->{_callbackUrl} = $callbackUrl;

        return $self;
}

sub _rest_call {
    my ($url, $headers, $authorization, $params) = @_;
    
    my $ua = Mojo::UserAgent->new;
    my $tx;
    if ($authorization) {
        $url = Mojo::URL->new($url)->userinfo($authorization);
        $tx = $ua->post($url => $headers => form => $params);
    } else {
        $tx = $ua->post($url => $headers => json => $params);
    }
    if ($tx->error) {
        return (from_json($tx->res->body), undef);
    } else {
        return (undef, from_json($tx->res->body));
    }

    
}

sub send_sms {
    my $self    = shift;
    my $params = {@_};
    my $message = $params->{text};
    my $recipientNumber = $params->{to};
    my $url = $self->{_baseUrl}.$self->{_appId};
    my $callbackUrl = $self->{_callbackUrl};

    if (! defined $message ) {
        warn "->send_sms(text) must be defined!";
        return;
    }
    if (! defined $recipientNumber ) {
        warn "->send_sms(to) must be defined!";
        return;
    }

    #Prevent injection attack!
    $recipientNumber =~ s/'//g;
    substr($recipientNumber, 0, 1, "+358") unless "+" eq substr($recipientNumber, 0, 1);
    $message =~ s/(")|(\$\()|(`)/\\"/g; #Sanitate " so it won't break the system( iconv'ed curl command )
    my $gsm0388 = decode("gsm0338",encode("gsm0338", $message));
    my $fragment_length = 160;
    if($message ne $gsm0388) {
        $fragment_length = 70;
        $message = $gsm0388;
    }
    
    my $message_length = length(encode("gsm0338", $message));

    my $fragments;
    if ($message_length > $fragment_length) {
        $fragments = ceil($message_length / $fragment_length);
    } else {
        $fragments = 1;
    }

    if ($fragments > 10) {
        die "message content is too big!";
        return;
    }

    my $authorization = $self->{_login}.":".$self->{_password};
    my $headers = {'Content-Type' => 'application/x-www-form-urlencoded'};
    my ($error, $token, $res, $revoke);
    ($error, $token) = _rest_call($url.'/token', $headers, $authorization, {grant_type => 'client_credentials'});

    if ($error) {
        die "Connection failed with: ". $error->{error};
        return;
    }

    $headers = {Authorization => "Bearer $token->{access_token}", 'Content-Type' => 'application/json'};

    my $reqparams = {
        recipient => {number => $recipientNumber},
        data => {message => $message, allowed_fragments => $fragments }
    };
    
    if ($callbackUrl) {
        my $msg_id = $params->{_message_id};
        my ( $uuid, $uuidstring );
        UUID::generate($uuid);
        UUID::unparse( $uuid, $uuidstring );
        my @params = ($uuidstring, $msg_id);
        my $dbh = C4::Context->dbh;
        my $sth = $dbh->prepare("INSERT INTO kohasuomi_sms_token (token,message_id) VALUES (?,?);");
        $sth->execute(@params);
        $callbackUrl =~ s/\{token\}|\{messagenumber\}/$uuidstring/g;
        $reqparams->{callback_url} = $callbackUrl;
    }

    ($error, $res) = _rest_call($url.'/sms', $headers, undef, $reqparams);

    if ($error) {
        die "Connection failed with: ". $error->{error};
        return;
    }
    elsif ($res->{status} eq "error") {
        die "Connection failed with: ". $res->{error};
        return;
    } else {
        return 1;
    }
}
1;
