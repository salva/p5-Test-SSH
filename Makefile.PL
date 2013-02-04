
use ExtUtils::MakeMaker;

my %prereq = ( 'Test::More' => '0',
               'URI'        => '1.60' );

if ($^O =~ /^MSWin/) {
    $prereq{'Win32::TieRegistry'} = '0.26';
}

WriteMakefile( NAME          => 'Test::SSH',
               VERSION_FROM  => 'lib/Test/SSH.pm',
               PREREQ_PM     => \%prereq,
               ABSTRACT_FROM => 'lib/Test/SSH.pm',
               AUTHOR        => 'Salvador Fandiño <sfandino@yahoo.com>');

