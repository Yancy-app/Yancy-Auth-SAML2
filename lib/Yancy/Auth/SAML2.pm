package Yancy::Auth::SAML2;
our $VERSION = '0.001';

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 SEE ALSO

=cut

use v5.42;
use Mojo::Base 'Yancy::Auth', -signatures;
use Yancy::Util qw( routify );

use Net::SAML2::IdP;
use Net::SAML2::Protocol::AuthnRequest;
use Net::SAML2::Binding::POST;
use Net::SAML2::Binding::Redirect;
use Net::SAML2::Protocol::Assertion;

has issuer => 'yancy.app';
has provider_name => 'saml';

# idp_metadata => app->home->child('GoogleIDPMetadata.xml')->slurp,
# idp_cacert => app->home->child('Google_2031-2-5-133433_SAML2_0.pem')->to_string,
# signing_key => app->home->child('jambalaya-rsa2048-priv-key.pem')->to_string

has idp_metadata => sub { die 'idp_metadata is required' };
has idp_cacert => sub { die 'idp_cacert is required' };
has signing_key => sub { die 'signing_key is required' };

has _idp => sub($self) {
  Net::SAML2::IdP->new_from_xml(
    xml => $self->idp_metadata->slurp,
    cacert => $self->idp_cacert->to_string,
  );
};

=method new

=cut

sub new($class, $app, @args) {
  my $self = $class->SUPER::new($app, @args);
  my $route = routify($self->route);
  $route->get('', { hidden => 1 })->to(
    cb => sub($c) {
      # Create the auth request
      my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
          issuer        => $self->issuer,
          destination   => $self->_idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
          provider_name => 'Yancy CMS',
      );

      # XXX: Store ID in database instead. I think this is supposed to be
      # marginally secret and/or not able to be tampered with.
      $c->session(saml_req_id => $authnreq->id);

      my $redirect = Net::SAML2::Binding::Redirect->new(
          key => $self->signing_key->to_string,
          cert => $self->_idp->cert('signing'),
          param => 'SAMLRequest',
          # The ssl_url destination for redirect
          url => $self->_idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
      );

      # Redirect user to URL
      my $url = $redirect->sign($authnreq->as_xml);
      $c->redirect_to($url);
    },
  );

  $route->post('', { hidden => 1 })->to(cb => sub($c) {
    # Handle the callback
    my $saml_response = $c->query('SAMLResponse');
    my $saml_post = Net::SAML2::Binding::POST->new(
      cacert => $self->idp_cacert->to_string,
    );
    my $ret = $saml_post->handle_response( $saml_response );
    # XXX: What do $ret?
    my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
        xml => decode_base64($saml_response)
    );
    my $is_valid = $assertion->valid( $self->issuer, $c->session('saml_req_id') );
    if (!$is_valid) {
      return $c->rendered(500);
    }

    my $user_id = $assertion->nameid;
    my $claims = $assertion->attributes;
    $self->start_session( $c, $user_id );
  });

  return $self;
}

1;
