package Test::SSH::Backend::Local;

use strict;
use warnings;

use File::Glob qw(:glob);

require Test::SSH::Backend::Base;
our @ISA = qw(Test::SSH::Backend::Base);

sub new {
    my ($class, %opts) = @_;
    my $sshd = $class->SUPER::new( port => 22,
                                   %opts,
                                   host => 'localhost',
                                   auth_method => 'publickey' );

    my @keys = $sshd->_user_private_keys;

    for my $cmd ('true', 'exit', 'echo foo', 'date') {
        if ($sshd->_try_local_cmd($cmd)) {
            for my $key (@keys) {
                $sshd->{private_key_path} = $key;
                return $sshd if $sshd->_try_remote_cmd($cmd);
            }
        }
    }
    ()
}

sub _user_private_keys {
    grep {
        my $fh;
        open $fh, '<', $_ and <$fh> =~ /\bBEGIN\b.*\bPRIVATE\s+KEY\b/
    } bsd_glob("~/.ssh/*", GLOB_TILDE);
}

1;
