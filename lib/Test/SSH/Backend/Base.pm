package Test::SSH::Backend::Base;

use strict;
use warnings;
use IPC::Run qw(run timeout);
use File::Spec;
use File::Glob qw(:glob);
use Carp;
use POSIX;

use Test::SSH::Patch::URI::ssh;

my @private = qw(timeout logger test_commands path user_keys private_dir requested_uri run_server c_params);
my @public  = qw(host port auth_method password user key_path);
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
            if (/^key_path=(.*)$/) {
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
                                           -i => $sshd->{key_path},
                                           -l => $sshd->{user},
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
                                                         -l => $sshd->{user},
                                                         -p => $sshd->{port},
                                                         -F => $dev_null,
                                                         -o => 'PreferredAuthentications=password,keyboard-interactive',
                                                         -o => 'BatchMode=no',
                                                         -o => 'StrictHostKeyChecking=no',
                                                         -o => "UserKnownHostsFile=$dev_null",
                                                         -o => 'NumberOfPasswordPrompts=1',
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
    local $@;
    my $ok = eval { run($cmd, '<', $dev_null, '>', $dev_null, '2>&1', timeout($sshd->{timeout})) };
    $sshd->_log($ok ? "command run successfully" : "command failed, (rc: $?)");
    $ok
}

sub _try_local_cmd_with_password {
    my ($sshd, $cmd) = @_;

    $sshd->_log("running command '@$cmd' with password");

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
    my $buffer = '';

    while (1) {
        if (time > $end) {
            kill ((time - $end > 3 ? 'KILL' : 'TERM'), $pid);
        }

        if (waitpid($pid, POSIX::WNOHANG()) > 0) {
            $sshd->_log("program ended with code $?");
            return $? == 0;
        }
        my $rv = '';
        vec($rv, fileno($pty), 1) = 1;
        if (select($rv, undef, undef, 1) > 0) {
            if (sysread($pty, $buffer, 4096, length($buffer))) {
                if ($buffer =~ s/.*[:?]\s*$//s) {
                    print $pty "$sshd->{password}\n";
                }
            }
            select(undef, undef, undef, 0.1);
        }
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
    local $@;
    eval { run([$cmd, @args], '<', $dev_null, '>', $dev_null, '2>&1') };
}

sub _test_server {
    my $sshd = shift;
    for my $cmd (@{$sshd->{test_commands}}) {
        if (defined $sshd->{requested_uri} or $sshd->_try_local_cmd($cmd)) {
            if ($sshd->_try_remote_cmd($cmd)) {
                $sshd->_log("connection ok");
                return 1;
            }
        }
    }
    ()
}

sub uri {
    my ($sshd, %opts) = @_;
    my $auth_method = $sshd->{auth_method};
    my $uri = URI->new;
    $uri->scheme('ssh');
    $uri->user($sshd->{user});
    $uri->host($sshd->{host});
    $uri->port($sshd->{port});
    if ($auth_method eq 'password') {
        $uri->password($opts{hide_passord} ? '*****' : $sshd->{password});
    }
    elsif ($auth_method eq 'publickey') {
        $uri->c_params(["key_path=$sshd->{key_path}"]);
    }
    $uri;
}

sub connection_params {
    my $sshd = shift;
    if (wantarray) {
        my @keys = qw(host port user);
        push @keys, ($sshd->{auth_method} eq 'password' ? 'password' : 'key_path');
        return map { $_ => $sshd->$_ } @keys;
    }
    else {
        return $sshd->uri;
    }
}

sub server_version {
    my $sshd = shift;
    unless (defined $sshd->{server_version}) {
        $sshd->_log("retrieving server version");
        require IO::Socket::INET;
        my $end = time + $sshd->{timeout};
        my $buffer = '';
        if (my $socket = IO::Socket::INET->new(PeerAddr => $sshd->{host},
                                               PeerPort => $sshd->{port},
                                               Timeout  => $sshd->{timeout},
                                               Proto    => 'tcp',
                                               Blocking => 0)) {
            while (time <= $end and $buffer !~ /\n/) {
                my $rv = '';
                vec($rv, fileno($socket), 1) = 1;
                if (select($rv, undef, undef, 1) > 0) {
                    sysread($socket, $buffer, 1024, length($buffer)) or last;
                }
            }
            if ($buffer =~ /^(.*)\n/) {
                $sshd->{server_version} = $1;
            }
            else {
                $sshd->_log("unable to retrieve server version");
            }
        }
        else {
            $sshd->_log("unable to connect to server", $!);
        }
    }
    $sshd->{server_version}
}

1;
