package Test::SSH::Backend::Base;

use strict;
use warnings;
use IPC::Run qw(run timeout);
use File::Spec;
use File::Glob qw(:glob);
use Carp;

my %slot = ( host => undef,
             port => 22,
             auth_method => undef,
             password => undef,
             username => undef,
             private_key_path => undef );

for my $slot (keys %slot) {
    no strict 'refs';
    *$slot = sub { shift->{$slot} }
}

sub new {
    my ($class, %opts) = @_;
    my $timeout = delete $opts{timeout} || 10;
    my $self = { timeout => $timeout };
    bless $self, $class;
    for my $slot (keys %slot) {
        my $v = delete $opts{$slot};
        $self->{$slot} = (defined $v ? $v : $slot{$slot});
    }

    unless (defined $self->{username}) {
        unless ($^O =~ /^Win/) {
            $self->{username} = getpwuid($>);
        }
        croak "unable to infer username" unless defined $self->{username};
    }

    return $self;
}

my $devnull = File::Spec->devnull;

sub _try_remote_cmd {
    my ($self, $cmd) = @_;
    my $ssh = $self->_find_ssh or return;

    if ($self->{auth_method} eq 'publickey') {
        return $self->_try_local_cmd([ $ssh,
                                       '-T',
                                       -i => $self->{private_key_path},
                                       -l => $self->{username},
                                       -p => $self->{port},
                                       -F => $devnull,
                                       -o => 'PreferredAuthentications=publickey',
                                       -o => 'BatchMode=yes',
                                       -o => 'StrictHostKeyChecking=no',
                                       -o => "UserKnownHostsFile=$devnull",
                                       '--',
                                       $self->{host},
                                       $cmd ]);
    }
    else {
        # FIXME: implement password authentication testing
        return
    }
}

sub _try_local_cmd {
    my ($self, $cmd) = @_;
    run($cmd, '<', $devnull, '>', $devnull, timeout($self->{timeout}));
}

sub _find_binaries {
    my ($self, @names) = @_;
    my @paths = File::Spec->path;
    if ($^O =~ /^Win/) {
        # look for SSH in common locations
    }
    else {
        push @paths, ( map { ( File::Spec->join($_, 'bin'),
                               File::Spec->join($_, 'sbin') ) }
                       map { File::Spec->rel2abs($_) }
                       map { bsd_glob($_, GLOB_TILDE|GLOB_NOCASE) }
                       qw( /
                           /usr
                           /usr/local
                           ~/
                           /usr/local/*ssh*
                           /opt/*SSH* ) );
    }

    my @bins;
    for my $path (@paths) {
        for my $name (@names) {
            my $fn = File::Spec->join($path, $name);
            if (-f $fn and -x $fn and -B $fn) {
                return $fn unless wantarray;
                push @bins, $fn;
            }
        }
    }
    return @bins;
}

sub _find_ssh {
    my $self = shift;
    for my $bin ($self->_find_binaries('ssh')) {
        my $out;
        if ( run [$bin, '-V'], '>', \$out, '2>&1', timeout($self->{timeout}) ) {
            return $bin if $out =~ /^OpenSSH[_\-](\d+\.\d+(?:p\d+))/m;
        }
    }
    return ();
}

sub uri {
    my $self = shift;
    my $userinfo = $self->{username};
    if    ($self->{auth_method} eq 'publickey') {
        $userinfo .= ";private_key_path=$self->{private_key_path}";
    }
    elsif ($self->{auth_method} eq 'password') {
        $userinfo .= ":$self->{password}"
    }
    "ssh://$userinfo\@$self->{host}:$self->{port}"
}


1;
