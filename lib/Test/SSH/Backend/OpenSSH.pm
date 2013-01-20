package Test::SSH::Backend::OpenSSH;

use strict;
use warnings;

require Test::SSH::Backend::Base;
our @ISA = qw(Test::SSH::Backend::Base);

sub new {
    my ($class, %opts) = @_;
    my $sshd = $class->SUPER::new(%opts);

    my @bins = $sshd->_find_binaries('sshd');
}



1;