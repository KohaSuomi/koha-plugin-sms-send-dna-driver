package Koha::Plugin::Fi::KohaSuomi::SMSSendDNADriver::Controllers::ReportController;

# This file is part of Koha.
#
# Koha is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.
#
# Koha is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with Koha; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

use Modern::Perl;

use Mojo::Base 'Mojolicious::Controller';
use Try::Tiny;
use Koha::Notice::Messages;
use C4::Context;

=head1 API

=cut

sub set {
    my $c = shift->openapi->valid_input or return;

    my $token = $c->validation->param('token');
    my $body = $c->req->json;
    my $status = $body->{status};
    my $delivery_note = $body->{error};
    my $notice;
    my $dbh = C4::Context->dbh;
    return try {
        my $sth = $dbh->prepare("SELECT message_id FROM kohasuomi_sms_token WHERE token = ?;");
        $sth->execute($token);
        my $notice_id = $sth->fetchrow;
        $notice = Koha::Notice::Messages->find($notice_id);

        if ($status eq "error") {
            # Delivery was failed. Set notice status to failed and add delivery
            $notice->set({
                status       => 'failed',
                failure_code => $delivery_note,
            })->store;
        }
        $sth = $dbh->prepare("DELETE FROM kohasuomi_sms_token WHERE message_id = ?;");
        $sth->execute($notice_id);
        return $c->render(status => 200, openapi => "");
    }
    catch {
        unless ($notice) {
            return $c->render( status  => 404,
                               openapi => { error => "Notice not found" } );
        } else {
            return $c->render( status  => 500,
                               openapi => { error => "Something went wrong, check the logs!" } );
        }
    };
}

1;