package Test::SSH::Backend::Base;

use strict;
use warnings;
use IPC::Run qw(run timeout);
use File::Spec;
use File::Glob qw(:glob);
use Carp;
use POSIX;

use Test::SSH::Patch::URI::ssh;

my @private = qw(timeout logger test_commands path user_keys private_dir requested_uri no_server_backends c_params);
my @public  = qw(host port auth_method password username private_key_path);
for my $accessor (@public) {
    no strict 'refs';
    *$accessor = sub { shift->{$accessor} }
}

sub new {
    my ($class, %opts) = @_;

    my $sshd = {};
    bless $sshd, $class;
    $sshd->{$_} = delete($opts{$_}) for (@public, @private);

    if (defined (my $uri_txt =  $sshd->{requested_uri})) {
        my $uri = URI->new($uri_txt);
        $uri->scheme('ssh') unless defined $uri->scheme;
        if ($uri->scheme ne 'ssh') {
            $sshd->_error("not a ssh URI '$uri'");
            return;
        }

        for my $k (qw(password host port user c_params)) {
            my $v = $uri->$k;
            $sshd->{$k} = $v if defined $v;
        }

        for (@{$opts{c_params} || []}) {
            if (/^private_key_path=(.*)$/) {
                $sshd->{user_keys} = [$1];
            }
        }
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
        my $auth_method = $sshd->{auth_method};
        if ($auth_method eq 'publickey') {
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
        elsif ($auth_method eq 'password') {
            return $sshd->_try_local_cmd_with_password([ $ssh,
                                                         '-T',
                                                         -l => $sshd->{username},
                                                         -p => $sshd->{port},
                                                         -F => $dev_null,
                                                         -o => 'PreferredAuthentications=password,keyboard-interactive',
                                                         -o => 'BatchMode=no',
                                                         -o => 'StrictHostKeyChecking=no',
                                                         -o => "UserKnownHostsFile=$dev_null",
                                                         '--',
                                                         $sshd->{host},
                                                         $cmd ]);
        }
    }
}

sub _try_local_cmd {
    my ($sshd, $cmd) = @_;
    $cmd = [$cmd] unless ref $cmd;
    $sshd->_log("running command '@$cmd'");
    my $ok = run($cmd, '<', $dev_null, '>', $dev_null, '2>&1', timeout($sshd->{timeout}));
    $sshd->_log($ok ? "command run successfully" : "command failed, (rc: $?)");
    $ok
}

sub _try_local_cmd_with_password {
    my ($sshd, $cmd) = @_;

    if ($^O =~ /^Win/) {
        $sshd->_error("password authentication not supported on inferior OS");
        return;
    }
    unless (eval {require IO::Pty; 1}) {
        $sshd->_error("IO::Pty not available");
        return;
    }

    my $pty = IO::Pty->new;
    my $pid = fork;
    unless ($pid) {
        unless (defined $pid) {
            $sshd->_error("fork failed: $!");
            return;
        }
        $pty->make_slave_controlling_terminal;
        if (open my $in, '</dev/null') {
            POSIX::dup2(fileno($in), 0);
        }
        if (open my $out, '>/dev/null') {
            POSIX::dup2(fileno($out), 1);
            POSIX::dup2(1, 2);
        }
        do { exec @$cmd };
        POSIX::_exit(1);
    }

    my $end = time + $sshd->{timeout};
    my $state = 'password';
    my $buffer = '';

    while (time <= $end) {
        if (waitpid($pid, POSIX::WNOHANG()) < 0) {
            return $? == 0;
        }
        my $bytes = sysread($pty, $buffer, 4096, length($buffer));
        if ($bytes) {
            if ($state eq 'password') {
                if ($buffer =~ /[:?]\s*$/) {
                    print $pty "$sshd->{password}\n";
                    $buffer = '';
                    $state = 'get_reply';
                }
            }
            elsif ($state eq 'get_reply') {
                if ($buffer =~ /\n/) {
                    $state = 'ending';
                }
            }
            else {
                $buffer = '';
            }
        }
        sleep(1);
    }
    return;
}


sub _find_binaries {
    my ($sshd, @cmds) = @_;
    $sshd->_log("resolving command(s) @cmds");
    my @path = @{$sshd->{path}};

    if (defined $sshd->{_ssh_executable}) {
        my $dir = File::Spec->join((File::Spec->splitpath($sshd->{_ssh_executable}))[0,1]);
        unshift @path, $dir, File::Spec->join($dir, File::Spec->updir, 'sbin');
    }

    my @bins;
    $sshd->_log("search path is " . join(":", @path));
    for my $path (@path) {
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
    my ($sshd, %opts) = @_;
    my $userinfo = $sshd->{username};
    if ($sshd->{auth_method} eq 'publickey') {
        $userinfo .= ";private_key_path=$sshd->{private_key_path}";
    }
    elsif ($sshd->{auth_method} eq 'password') {
        $userinfo .= ':' . ($opts{hide_password} ? '*****' : $sshd->{password});
    }
    "ssh://$userinfo\@$sshd->{host}:$sshd->{port}"
}

sub _mkdir {
    my ($sshd, $dir) = @_;
    if (defined $dir) {
        -d $dir and return 1;
        if (mkdir($dir, 0700) and -d $dir) {
            $sshd->_log("directory '$dir' created");
            return 1;
        }
        $sshd->_error("unable to create directory '$dir'", $!);
    }
    return;
}

sub _private_dir {
    my ($sshd, $subdir) = @_;
    my $slot = "private_dir";
    my $pdir = $sshd->{$slot};
    $sshd->_mkdir($pdir) or return;

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

sub _test_server {
    my $sshd = shift;
    for my $cmd (@{$sshd->{test_commands}}) {
        if (defined $sshd->{uri} or $sshd->_try_local_cmd($cmd)) {
            if ($sshd->_try_remote_cmd($cmd)) {
                $sshd->_log("connection ok");
                return 1;
            }
        }
    }
    ()
}

1;
