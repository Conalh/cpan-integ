use strict;
use warnings;
use Test::More;
use FindBin ();
use lib "$FindBin::Bin/../lib";
use File::Temp qw(tempdir);
use App::CpanInteg;

plan skip_all => 'live network test; set CPAN_INTEG_LIVE=1 to run'
    unless $ENV{CPAN_INTEG_LIVE};

my $dir   = tempdir(CLEANUP => 1);
my $snapf = "$dir/cpanfile.snapshot";
my $lockf = "$dir/cpanfile.integrity";

open my $w, '>', $snapf or die $!;
print {$w} <<'SNAP';
DISTRIBUTIONS
  Try-Tiny-0.32
    pathname: E/ET/ETHER/Try-Tiny-0.32.tar.gz
SNAP
close $w;

is App::CpanInteg::cmd_pin('--snapshot', $snapf, '--out', $lockf), 0, 'pin returns 0';
ok -s $lockf, 'lockfile written and non-empty';

is App::CpanInteg::cmd_verify('--integrity', $lockf), 0, 'verify clean lock returns 0';
is App::CpanInteg::cmd_verify('--integrity', $lockf, '--snapshot', $snapf), 0,
    'verify with snapshot consistency returns 0';

my $cache = "$dir/mirror";
is App::CpanInteg::cmd_fetch('--integrity', $lockf, '--cache', $cache), 0, 'fetch returns 0';
ok -s "$cache/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz",
    'verified artifact stored in authors/id mirror layout';

# Tamper: corrupt the hash (keep it 64 hex so it still parses).
my $content = do { open my $r, '<', $lockf; local $/; <$r> };
$content =~ s/sha256:[0-9a-f]{4}/sha256:dead/;
open my $t, '>', $lockf or die $!;
print {$t} $content;
close $t;

is App::CpanInteg::cmd_verify('--integrity', $lockf), 1, 'verify fails (exit 1) on tampered hash';

done_testing;
