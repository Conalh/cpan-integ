use strict;
use warnings;
use Test::More;
use File::Temp ();
use App::CpanInteg::CpmResolver;

# Offline test of the cpm glue resolver's mapping logic: package -> pinned
# distribution -> checksum, mirror-mode URI rewriting, and error cases. The
# in-fetch verification itself (patched cpm) is exercised by the cpm-integrity
# CI job; here we only need the resolver's resolve() contract.

my $snapshot = 'examples/cpanfile.snapshot';
ok -f $snapshot, "example snapshot present";

# A lockfile pinning exactly the snapshot's distributions (fake but well-formed
# digests; resolution does not download anything).
my $A = 'a' x 64;
my $B = 'b' x 64;
my $lock = File::Temp->new(SUFFIX => '.integrity');
print {$lock} <<"LOCK";
# cpanfile.integrity - test fixture
pkg:cpan/ETHER/Try-Tiny\@0.32 sha256:$A https://cpan.metacpan.org/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz
pkg:cpan/DAGOLDEN/Capture-Tiny\@0.50 sha256:$B https://cpan.metacpan.org/authors/id/D/DA/DAGOLDEN/Capture-Tiny-0.50.tar.gz
LOCK
close $lock;

my $ctx = {};   # resolver ignores $ctx beyond the positional slot

# --- default mode: resolve against the pinned download_url -----------------
my $r = App::CpanInteg::CpmResolver->new($ctx,
    "snapshot=$snapshot", "integrity=$lock");

my $res = $r->resolve($ctx, { package => 'Try::Tiny' });
is $res->{source},   'cpan',                              'source is cpan';
is $res->{distfile}, 'E/ET/ETHER/Try-Tiny-0.32.tar.gz',   'distfile is the snapshot pathname';
is $res->{uri},      'https://cpan.metacpan.org/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz',
                                                           'uri is the pinned download_url';
is $res->{checksum}, "sha256:$A",                          'checksum is the pinned sha256';
is $res->{version},  '0.32',                               'version from provides';
is_deeply $res->{provides}, [ { package => 'Try::Tiny', version => '0.32' } ],
                                                           'provides carried through';

# a different package resolves to its own pinned dist
my $cap = $r->resolve($ctx, { package => 'Capture::Tiny' });
is $cap->{checksum}, "sha256:$B", 'second package maps to its own pinned digest';

# --- strict: a package not pinned in the lock is refused -------------------
my $miss = $r->resolve($ctx, { package => 'Path::Tiny' });   # in snapshot, NOT in lock
ok $miss->{error}, 'package present in snapshot but absent from lock -> error';
like $miss->{error}, qr/no pinned checksum/, 'error explains the missing pin';

my $unknown = $r->resolve($ctx, { package => 'No::Such::Module' });
ok $unknown->{error}, 'unknown package -> error';

# --- mirror mode: rewrite the URI to a local verified mirror ---------------
my $rm = App::CpanInteg::CpmResolver->new($ctx,
    "snapshot=$snapshot", "integrity=$lock", "mirror=file:///tmp/m");
my $mres = $rm->resolve($ctx, { package => 'Try::Tiny' });
is $mres->{uri}, 'file:///tmp/m/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz',
                                                           'mirror mode rewrites uri to the local mirror';
is $mres->{checksum}, "sha256:$A", 'mirror mode still carries the pinned digest';

done_testing;
