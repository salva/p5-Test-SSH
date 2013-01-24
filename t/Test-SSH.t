#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 4;

use_ok('Test::SSH');

ok(eval { Test::SSH->new; 1});
ok(eval { Test::SSH->new(backends=>[qw(Remote)]); 1});
ok(eval { Test::SSH->new(backends=>[qw(OpenSSH)]); 1});


