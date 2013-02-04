package Test::SSH::Backend::Remote;

use strict;
use warnings;

require Test::SSH::Backend::Base;
our @ISA = qw(Test::SSH::Backend::Base);

sub new {
    my ($class, %opts) = @_;
    my $sshd = $class->SUPER::new(%opts);

    if (defined $sshd->{password}) {
        $sshd->_log("trying to authenticate using given password");
        $sshd->{auth_method} = 'password';
        if ($sshd->_test_server) {
            $sshd->_log("the given password can be used to connect to host");
            return $sshd;
        }
    }

    $sshd->_log("trying to authenticate using keys");
    $sshd->{auth_method} = 'publickey';
    for my $key (@{$sshd->{openssh_user_keys}}, @{$sshd->{putty_user_keys}}) {
        $sshd->_log("trying user key '$key'");
        $sshd->_use_key($key) or next;
        if ($sshd->_test_server) {
            $sshd->_log("key '$key' can be used to connect to host");
            return $sshd;
        }
    }
    ()
}

1;
