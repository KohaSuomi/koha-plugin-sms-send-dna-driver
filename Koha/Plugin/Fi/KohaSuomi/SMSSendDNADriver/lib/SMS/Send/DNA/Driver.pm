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
        $self->{callbackUrl} = $callbackUrl;

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
        return ($tx->error, undef);
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
    my $fragment_length = 160;
    if($message =~ /[^\@£\$¥èéùìòÇØøÅå&#916;_&#934;&#915;&#923;&#937;&#928;&#936;&#931;&#920;&#926;ÆæßÉ !"#¤%\&\'\(\)\*\+\,\-\.\/0-9:;<=>\?¡A-ZÄÖÑÜ§¿a-zäöñüà]/ ) {
        $fragment_length = 70;
    }
    my $gsm0338 = encode("gsm0338", $message);
    my $message_length = length($gsm0338);

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
        die "Connection failed with: ". $error->{message};
        return;
    }

    $headers = {Authorization => "Bearer $token->{access_token}", 'Content-Type' => 'application/json'};

    my $params = {
        recipient => {number => $recipientNumber},
        data => {message => $message, allowed_fragments => $fragments }
    };
    
    if ($callbackUrl) {
        my $msg_id = $params->{_message_id};
        $callbackUrl =~ s/\{notice_id\}|\{messagenumber\}/$msg_id/g;
        $params->{callback_url} = $callbackUrl;
    }

    ($error, $res) = _rest_call($url.'/sms', $headers, undef, $params);

    if ($error) {
        die "Connection failed with: ". $error->{message};
        return;
    }
    elsif ($res->{status} eq "error") {
        die "Connection failed with: ". $res->{error};
        return;
    } else {
        ($error, $revoke) = _rest_call($url.'/revoke', {'Content-Type' => 'application/x-www-form-urlencoded'}, $authorization, {token => $token->{access_token}});
        return 1;
    }
}
1;
