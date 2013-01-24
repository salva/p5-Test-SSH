package Test::SSH::Backend::OpenSSH;

use strict;
use warnings;

use IO::Socket::INET;

use IPC::Run qw(start finish);

require Test::SSH::Backend::Base;
our @ISA = qw(Test::SSH::Backend::Base);

sub new {
    my ($class, %opts) = @_;
    my $sshd = $class->SUPER::new(%opts, auth_method => 'publickey');
    unless ($sshd->{run_server}) {
        $sshd->_log("backend skipped because run_server is set to false");
        return;
    }

    my $bin = $sshd->_sshd_executable or return;
    $sshd->_create_keys or return;
    my $run_dir = $sshd->_run_dir;
    my $port = $sshd->{port} = $sshd->_find_unused_port;

    $sshd->_write_config(HostKey            => $sshd->{host_key_path},
                         AuthorizedKeysFile => $sshd->_user_key_path_quoted . ".pub",
                         AllowUsers         => $sshd->{user}, # only user running the script can log
                         AllowTcpForwarding => 'yes',
                         GatewayPorts       => 'no', # bind port forwarder listener to localhost only
                         ChallengeResponseAuthentication => 'no',
                         PasswordAuthentication => 'no',
                         Port               => $port,
                         ListenAddress      => "localhost:$port",
                         LogLevel           => 'INFO',
                         PermitRootLogin    => 'yes',
                         PidFile            => "$run_dir/sshd.pid",
                         PrintLastLog       => 'no',
                         PrintMotd          => 'no',
                         UseDNS             => 'no')
        or return;

    my @args = ('-D', # no daemon
                '-e', # send output to STDERR
                '-f', $sshd->{config_file});


    $sshd->_log("starting SSH server '$bin'");

    unless ($sshd->{harness} = start([$bin, @args],
                                     '<', $sshd->_dev_null,
                                     '>', "$run_dir/sshd.out",
                                     '2>', "$run_dir/sshd.err")) {
        $sshd->_error("unable to start SSH server at '$bin' on port $port", $!);
        return undef;
    }

    $sshd->_log("SSH server listening on port $port");

    $sshd->_log("trying to authenticate using keys");
    $sshd->{auth_method} = 'publickey';
    for my $key (@{$sshd->{user_keys}}) {
        $sshd->_log("trying user key '$key'");
        $sshd->{key_path} = $key;
        if ($sshd->_test_server) {
            $sshd->_log("key '$key' can be used to connect to host");
            return $sshd;
        }
    }
    ()
}

sub _run_dir {
    my $sshd = shift;
    unless (defined $sshd->{run_dir}) {
        $sshd->{run_dir} = $sshd->_private_dir("openssh/run/$$");
    }
    $sshd->{run_dir}
}

sub _run_dir_last { shift->_private_dir("openssh/run/last") }

sub _write_config {
    my $sshd = shift;
    my $fn = $sshd->{config_file} = "$sshd->{run_dir}/sshd_config";
    if (open my $fn, '>', $fn) {
        while (@_) {
            my $k = shift;
            my $v = shift;
            print $fn "$k=$v\n";
        }
        close $fn and return 1
    }
    $sshd->_error("unable to create sshd configuration file at '$fn': $!");
    ()
}

sub _is_server_running {
    my $sshd = shift;
    if (my $h = $sshd->{harness}) {
        return 1 if $h->pumpable;
    }
    $sshd->_error("SSH server is not running");
    return
}

sub DESTROY {
    my $sshd = shift;
    local ($@, $!, $?, $^E);
    if (my $h = $sshd->{harness}) {
        $sshd->_log("stopping SSH server");
        eval {
            $h->kill_kill;
            $sshd->_log("server stopped");
        };
    }
    my $run_dir = $sshd->{run_dir};
    my $last = $sshd->_run_dir_last;

    if (defined $run_dir) {
        for my $signal (qw(TERM TERM TERM TERM KILL)) {
            open my $fh, '<', "$run_dir/sshd.pid" or last;
            my $pid = <$fh>;
            defined $pid or last;
            chomp $pid;
            $pid or last;
            $sshd->_log("sending $signal signal to server (pid: $pid)");
            kill $signal => $pid;
            sleep 1;
        }
        system 'rm', '-Rf', '--', $last if -d $last;
        rename $sshd->{run_dir}, $last;
        $sshd->_log("SSH server logs moved to '$last'");
    }
}

sub _sshd_executable { shift->_find_executable('sshd', '-zalacain', 5) }

sub _ssh_keygen_executable { shift->_find_executable('ssh-keygen') }

sub _create_key {
    my ($sshd, $fn) = @_;
    -f $fn and -f "$fn.pub" and return 1;
    $sshd->_log("generating key '$fn'");
    my $tmpfn = join('.', $fn, $$, int(rand(9999999)));
    if ($sshd->_run('ssh_keygen', -t => 'dsa', -b => 1024, -f => $tmpfn, -P => '')) {
        unlink $fn;
        unlink "$fn.pub";
        if (rename $tmpfn, $fn and
            rename "$tmpfn.pub", "$fn.pub") {
            $sshd->_log("key generated");
            return 1;
        }
    }
    $sshd->_error("key generation failed");
    return;
}

sub _user_key_path_quoted {
    my $sshd = shift;
    my $key = $sshd->{user_key_path};
    $key =~ s/%/%%/g;
    $key;
}

sub _create_keys {
    my $sshd = shift;
    my $kdir = $sshd->_private_dir('openssh/keys') or return;
    my $user_key = $sshd->{user_key_path} = "$kdir/user_key";
    my $host_key = $sshd->{host_key_path} = "$kdir/host_key";
    $sshd->{user_keys} = [$user_key];
    $sshd->_create_key($user_key) and
    $sshd->_create_key($host_key);
}

sub _find_unused_port {
    my $sshd = shift;
    $sshd->_log("looking for an unused TCP port");
    for (1..32) {
        my $port = 5000 + int rand 27000;
        unless (IO::Socket::INET->new(PeerAddr => "localhost:$port",
                                      Proto => 'tcp',
                                      Timeout => 10)) {
            $sshd->_log("port $port is available");
            return $port;
        }
    }
    $sshd->_error("Can't find free TCP port for SSH server");
    return;
}

1;
