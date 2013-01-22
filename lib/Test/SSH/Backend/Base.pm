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
    my $sshd = {};
    bless $sshd, $class;
    $sshd->{$_} = delete($opts{$_}) for qw(timeout logger);
    for my $slot (keys %slot) {
        my $v = delete $opts{$slot};
        $sshd->{$slot} = (defined $v ? $v : $slot{$slot});
    }

    unless (defined $sshd->{username}) {
        unless ($^O =~ /^Win/) {
            $sshd->{username} = getpwuid($>);
        }
        croak "unable to infer username" unless defined $sshd->{username};
    }

    $sshd->_log("starting backend of class '$class'");

    return $sshd;
}

sub _log {
    local ($@, $!, $?, $^E);
    my $sshd = shift;
    eval { $sshd->{logger}->(join(': ', @_)) }
}

sub _error { shift->_log(error => @_) }

my $dev_null = File::Spec->devnull;
sub _dev_null { $dev_null }

sub _is_server_running { 1 }

sub _try_remote_cmd {
    my ($sshd, $cmd) = @_;
    my $ssh = $sshd->_ssh_executable or return;

    if ($sshd->_is_server_running) {
        if ($sshd->{auth_method} eq 'publickey') {
            return $sshd->_try_local_cmd([ $ssh,
                                           '-T',
                                           -i => $sshd->{private_key_path},
                                           -l => $sshd->{username},
                                           -p => $sshd->{port},
                                           -F => $dev_null,
                                           -o => 'PreferredAuthentications=publickey',
                                           -o => 'BatchMode=yes',
                                           -o => 'StrictHostKeyChecking=no',
                                           -o => "UserKnownHostsFile=$dev_null",
                                           '--',
                                           $sshd->{host},
                                           $cmd ]);
        }
        else {
            $sshd->_error("unable to check commands when password authentication is being used");
            return;
            # FIXME: implement password authentication testing
        }
    }
}

sub _try_local_cmd {
    my ($sshd, $cmd) = @_;
    run($cmd, '<', $dev_null, '>', $dev_null, timeout($sshd->{timeout}));
}

sub _find_binaries {
    my ($sshd, @cmds) = @_;
    $sshd->_log("resolving command(s) @cmds");
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

    if (defined $sshd->{_ssh_executable}) {
        my $dir = File::Spec->join((File::Spec->splitpath($sshd->{_ssh_executable}))[0,1]);
        unshift @paths, $dir, File::Spec->join($dir, File::Spec->updir, 'sbin');
    }

    my @bins;
    $sshd->_log("search path is " . join(":", @paths));
    for my $path (@paths) {
        for my $cmd (@cmds) {
            my $fn = File::Spec->join($path, $cmd);
            if (-f $fn) {
                $sshd->_log("candidate found at $fn");
                unless (-x $fn) {
                    $sshd->_log("file $fn is not executable");
                    next;
                }
                unless (-B $fn) {
                    $sshd->_log("file $fn looks like a wrapper, ignoring it");
                    next;
                }
                return $fn unless wantarray;
                push @bins, $fn;
            }
        }
    }
    return @bins;
}

sub _find_executable {
    my ($sshd, $cmd, $version_flags, $min_version) = @_;
    my $slot = "${cmd}_executable";
    defined $sshd->{$slot} and return $sshd->{$slot};
    if (defined $version_flags) {
        for my $bin ($sshd->_find_binaries($cmd)) {
            my $out;
            $sshd->_log("checking version of '$bin'");
            run [$bin, $version_flags], '>', \$out, '2>&1', timeout($sshd->{timeout});
            if (defined $out) {
                if (my ($ver, $mayor) = $out =~ /^(OpenSSH[_\-](\d+)\.\d+(?:p\d+))/m) {
                    if (!defined($min_version) or $mayor >= $min_version) {
                        $sshd->_log("executable version is $ver, selecting it!");
                        $sshd->{$slot} = $bin;
                        last;
                    }
                    else {
                        $sshd->_log("executable is too old ($ver), $min_version.x required");
                        next;
                    }
                }
            }
            $sshd->_log("command failed");
        }
    }
    else {
        $sshd->{$slot} = $sshd->_find_binaries($cmd)
    }
    if (defined (my $bin = $sshd->{$slot})) {
        $sshd->_log("command '$cmd' resolved as '$sshd->{$slot}'");
        return $bin;
    }
    else {
        $sshd->_error("no executable found for command '$cmd'");
        return;
    }
}

sub _ssh_executable { shift->_find_executable('ssh', '-V', 5) }

sub uri {
    my $sshd = shift;
    my $userinfo = $sshd->{username};
    if    ($sshd->{auth_method} eq 'publickey') {
        $userinfo .= ";private_key_path=$sshd->{private_key_path}";
    }
    elsif ($sshd->{auth_method} eq 'password') {
        $userinfo .= ":$sshd->{password}"
    }
    "ssh://$userinfo\@$sshd->{host}:$sshd->{port}"
}

sub _mkdir {
    my ($sshd, $dir, $mask) = @_;
    if (defined $dir) {
        $mask = 0700 unless defined $mask;
        unless (-d $dir) {
            unless (mkdir($dir, $mask) and -d $dir) {
                $sshd->_save_error("Unable to create directory '$dir'", $!);
                return
            }
        }
        chmod $mask, $dir;
        return 1;
    }
    return;
}

sub _private_dir {
    my ($sshd, $subdir) = @_;
    my $slot = "private_dir";
    my $pdir = $sshd->{$slot};
    unless (defined $pdir) {
        unless ($^O =~ /^Win/) {
            ($pdir) = bsd_glob("~/.libtest-ssh-perl", GLOB_TILDE|GLOB_NOCHECK);
        }
        unless (defined $pdir) {
            $pdir = File::Spec->join(File::Temp::tempdir(CLEANUP => 1),
                                     "libtest-ssh-perl");
        }
        $sshd->_mkdir($pdir) or return;
        $sshd->{$slot} = $pdir;
    };

    if (defined $subdir) {
        for my $sd (split /\//, $subdir) {
            $slot .= "/$sd";
            if (defined $sshd->{$slot}) {
                $pdir = $sshd->{$slot};
            }
            else {
                $pdir = File::Spec->join($pdir, $sd);
                $sshd->_mkdir($pdir) or return;
                $sshd->{$slot} = $pdir;
            }
        }
    }
    return $pdir;
}

sub _run {
    my ($sshd, $cmd, @args) = @_;
    if (my $method = ($sshd->can("${cmd}_executable") or $sshd->can("_${cmd}_executable"))) {
        $cmd = $sshd->$method or return;
    }
    run([$cmd, @args], '<', $dev_null, '>', $dev_null, '2>&1');
}

1;
