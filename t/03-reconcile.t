use strict;
use warnings;
use Test::More;
use FindBin ();
use lib "$FindBin::Bin/../lib";
use App::CpanInteg;

my $A = 'a' x 64;
my $B = 'b' x 64;
my $C = 'c' x 64;

my $snap = App::CpanInteg::parse_snapshot(<<'SNAP');
DISTRIBUTIONS
  Try-Tiny-0.32
    pathname: E/ET/ETHER/Try-Tiny-0.32.tar.gz
  Capture-Tiny-0.50
    pathname: D/DA/DAGOLDEN/Capture-Tiny-0.50.tar.gz
SNAP

my $lock_ok = App::CpanInteg::parse_lockfile(
      "pkg:cpan/ETHER/Try-Tiny\@0.32 sha256:$A https://x/E/ET/ETHER/Try-Tiny-0.32.tar.gz\n"
    . "pkg:cpan/DAGOLDEN/Capture-Tiny\@0.50 sha256:$B https://x/D/DA/DAGOLDEN/Capture-Tiny-0.50.tar.gz\n"
);
is_deeply [ App::CpanInteg::reconcile($snap, $lock_ok) ], [], 'consistent snapshot/lock: no problems';

my $lock_missing = App::CpanInteg::parse_lockfile(
    "pkg:cpan/ETHER/Try-Tiny\@0.32 sha256:$A https://x/E/ET/ETHER/Try-Tiny-0.32.tar.gz\n"
);
ok( ( grep { /missing from integrity lock: Capture-Tiny-0.50\.tar\.gz/ } App::CpanInteg::reconcile($snap, $lock_missing) ),
    'snapshot dist missing from lock is detected' );

my $lock_extra = App::CpanInteg::parse_lockfile(
      "pkg:cpan/ETHER/Try-Tiny\@0.32 sha256:$A https://x/E/ET/ETHER/Try-Tiny-0.32.tar.gz\n"
    . "pkg:cpan/DAGOLDEN/Capture-Tiny\@0.50 sha256:$B https://x/D/DA/DAGOLDEN/Capture-Tiny-0.50.tar.gz\n"
    . "pkg:cpan/EVIL/Sneaky\@9.99 sha256:$C https://x/E/EV/EVIL/Sneaky-9.99.tar.gz\n"
);
ok( ( grep { /not present in snapshot: Sneaky-9\.99\.tar\.gz/ } App::CpanInteg::reconcile($snap, $lock_extra) ),
    'lock entry absent from snapshot is detected' );

my $snap_ns = App::CpanInteg::parse_snapshot(<<'SNAP');
DISTRIBUTIONS
  Weird
    pathname: git://example.com/weird.git
SNAP
ok( ( grep { /non-CPAN source not allowed/ } App::CpanInteg::reconcile($snap_ns, []) ),
    'nonstandard source rejected by default' );
ok( !( grep { /non-CPAN source not allowed/ } App::CpanInteg::reconcile($snap_ns, [], allow_nonstandard => 1) ),
    'nonstandard source allowed with flag' );

done_testing;
