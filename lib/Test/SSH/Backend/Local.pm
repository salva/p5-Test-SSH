package Test::SSH::Backend::Local;

use strict;
use warnings;

use File::Glob qw(:glob);

require Test::SSH::Backend::Base;
our @ISA = qw(Test::SSH::Backend::Base);

sub new {
    my ($class, %opts) = @_;
    my $sshd = $class->SUPER::new( %opts,
                                   auth_method => 'publickey' );

    for my $key (@{$sshd->{user_keys}}) {
        $sshd->_log("trying user key '$key'");
        $sshd->{private_key_path} = $key;
        if ($sshd->_test_server) {
            $sshd->_log("key '$key' can be used to connect to host");
            return $sshd;
        }
    }
    ()
}

1;
