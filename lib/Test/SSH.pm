package Test::SSH;

our $VERSION = '0.01';

use strict;
use warnings;

require Test::More;

my @default_backends = qw(Local OpenSSH);

sub sshd {
    my ($class, %opts) = @_;

    my $be = delete $opts{backends};
    my @be = ( defined $ENV{TEST_SSH_TARGET} ? qw(Remote) :
               defined $be                   ? @$be       :
                                               @default_backends );

    $opts{timeout} = 10 unless defined $opts{timeout};
    $opts{logger} = sub { Test::More::diag("Test::SSH > @_") }
        unless defined $opts{logger};

    for my $be (@be) {
        my $class = "Test::SSH::Backend::$be";
        eval "require $class; 1" or die;
        my $sshd = $class->new(%opts) or next;
        return $sshd;
    }
    return;
}

1;
__END__

=head1 NAME

Test::SSH - Perl extension for testing SSH modules.

=head1 SYNOPSIS

  use Test::SSH;
  my $sshd = Test::SSH->sshd or skip_all;

  my %opts;
  $opts{host} = $sshd->host();
  $opts{port} = $sshd->port();
  $opts{user} = $sshd->username();
  given($sshd->auth_method) {
    when('password') {
      $opts{password} = $sshd->password;
    }
    when('publickey') {
      $opts{key_path} = $sshd->private_key_path;
    }
  }

  my $openssh = Net::OpenSSH->new(%opts);
  # or...
  my $anyssh  = Net::SSH::Any->new(%opts);
  # or...


=head1 DESCRIPTION

This module tries to configure and launch a private SSH daemon to be
used for testing SSH client modules.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Salvador FandiE<ntilde>o (sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
