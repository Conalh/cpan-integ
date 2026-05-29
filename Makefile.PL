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

    # Minimal dependency footprint. Parsing, hashing, and lockfile handling use
    # core modules; live HTTPS fetching needs Perl TLS support, which is NOT
    # core. The IO::Socket::SSL / Net::SSLeay versions match HTTP::Tiny's
    # documented TLS requirements.
    PREREQ_PM => {
        'HTTP::Tiny'      => 0,
        'JSON::PP'        => 0,
        'Digest::SHA'     => 0,
        'IO::Socket::SSL' => '1.56',
        'Net::SSLeay'     => '1.49',
    },

    META_MERGE => {
        'meta-spec' => { version => 2 },
    },
);
