package Test::SSH;

our $VERSION = '0.01';

use strict;
use warnings;

use Carp;
use File::Glob qw(:glob);
require File::Spec;
require Test::More;

my (@extra_path, @default_user_keys, $default_username, $private_dir);

if ( $^O =~ /^Win/) {
    require Win32;
    $default_username = Win32::LoginName();
}
else {
    @extra_path = ( map { File::Spec->join($_, 'bin'), File::Spec->join($_, 'sbin') }
                    map { File::Spec->rel2abs($_) }
                    map { bsd_glob($_, GLOB_TILDE|GLOB_NOCASE) }
                    qw( /
                        /usr
                        /usr/local
                        ~/
                        /usr/local/*ssh*
                        /opt/*SSH* ) );

    @default_user_keys = bsd_glob("~/.ssh/*", GLOB_TILDE);

    $default_username = getpwuid($>);

    ($private_dir) = bsd_glob("~/.libtest-ssh-perl", GLOB_TILDE|GLOB_NOCHECK);
}

@default_user_keys = grep {
    my $fh;
    open $fh, '<', $_ and <$fh> =~ /\bBEGIN\b.*\bPRIVATE\s+KEY\b/
} @default_user_keys;


my @default_path = grep { -d $_ } File::Spec->path, @extra_path;

unless (defined $private_dir) {
    require File::temp;
    $private_dir = File::Spec->join(File::Temp::tempdir(CLEANUP => 1),
                                    "libtest-ssh-perl");
}

my $default_logger = sub { Test::More::diag("Test::SSH > @_") };

my %defaults = ( backends      => [qw(Remote OpenSSH)],
                 timeout       => 10,
                 port          => 22,
                 host          => 'localhost',
                 username      => $default_username,
                 test_commands => ['true', 'exit', 'echo foo', 'date'],
                 path          => \@default_path,
                 user_keys     => \@default_user_keys,
                 private_dir   => $private_dir,
                 logger        => $default_logger,
               );

sub sshd {
    my ($class, %opts) = @_;
    defined $opts{$_} or $opts{$_} = $defaults{$_} for keys %defaults;

    if (defined (my $target = $ENV{TEST_SSH_TARGET})) {
        $opts{requested_uri} = $target;
        $opts{no_server_backends} = 1;
    }

    for my $be (@{delete $opts{backends}}) {
        $be =~ /^\w+$/ or croak "bad backend name '$be'";
        my $class = "Test::SSH::Backend::$be";
        eval "require $class; 1" or die;
        my $sshd = $class->new(%opts) or next;
        $sshd->_log("connection uri", $sshd->uri(hide_password => 1));
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
