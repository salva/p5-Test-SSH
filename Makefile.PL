
use ExtUtils::MakeMaker;

WriteMakefile( NAME          => 'Test::SSH',
               VERSION_FROM  => 'lib/Test/SSH.pm',
               PREREQ_PM     => { Test::More => '0' },
               ABSTRACT_FROM => 'lib/Test/SSH.pm',
               AUTHOR        => 'Salvador Fandiño <sfandino@yahoo.com>');

