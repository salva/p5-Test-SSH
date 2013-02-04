use ExtUtils::MakeMaker;
use utf8;

my %prereq = ( 'Test::More'  => '0',
               'URI'         => '1.60',
               'Tie::IxHash' => '0' );

if ($^O =~ /^MSWin/) {
    $prereq{'Win32::TieRegistry'} = '0.26';
}

WriteMakefile( NAME          => 'Test::SSH',
               VERSION_FROM  => 'lib/Test/SSH.pm',
               PREREQ_PM     => \%prereq,
               ABSTRACT_FROM => 'lib/Test/SSH.pm',
               AUTHOR        => 'Salvador Fandiño <sfandino@yahoo.com>',
               META_MERGE    => {
                   resources => {
                       repository => 'https://github.com/salva/p5-Test-SSH',
                   },
               },
);

