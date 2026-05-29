use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'App::CpanInteg',
    VERSION_FROM     => 'lib/App/CpanInteg.pm',
    ABSTRACT         => 'Consumer-side install-time integrity verification for CPAN distributions',
    AUTHOR           => 'Conal Hickey',
    LICENSE          => 'perl_5',
    MIN_PERL_VERSION => '5.014',
    EXE_FILES        => ['bin/cpan-integ'],

    # Deliberately core-only: a supply-chain tool should not widen its own
    # attack surface. All of these ship with Perl >= 5.14.
    PREREQ_PM => {
        'HTTP::Tiny'     => 0,
        'JSON::PP'       => 0,
        'Digest::SHA'    => 0,
        'IO::Socket::SSL' => 0,
    },

    META_MERGE => {
        'meta-spec' => { version => 2 },
    },
);
