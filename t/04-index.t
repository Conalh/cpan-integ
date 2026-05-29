use strict;
use warnings;
use Test::More;
use FindBin ();
use lib "$FindBin::Bin/../lib";
use App::CpanInteg;

my $snap = App::CpanInteg::parse_snapshot(<<'SNAP');
DISTRIBUTIONS
  Try-Tiny-0.32
    pathname: E/ET/ETHER/Try-Tiny-0.32.tar.gz
    provides:
      Try::Tiny 0.32
      Try::Tiny::Catch 0.32
    requirements:
      ExtUtils::MakeMaker 0
  Not-Locked-1.0
    pathname: X/XX/XXX/Not-Locked-1.0.tar.gz
    provides:
      Not::Locked 1.0
    requirements:
      ExtUtils::MakeMaker 0
SNAP

is scalar(@{ $snap->[0]{provides} }), 2, 'two provides parsed for first dist';
is $snap->[0]{provides}[0]{module}, 'Try::Tiny', 'provides module captured';
is $snap->[1]{provides}[0]{version}, '1.0', 'provides version captured';

my $H = 'a' x 64;
# lock contains ONLY Try-Tiny, not Not-Locked
my $lock = App::CpanInteg::parse_lockfile(
    "pkg:cpan/ETHER/Try-Tiny\@0.32 sha256:$H https://cpan.metacpan.org/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz\n"
);

my ($idx, $count) = App::CpanInteg::build_02packages($snap, $lock, date => 'Thu Jan  1 00:00:00 1970 GMT');
is $count, 2, 'two modules indexed (only from the locked dist)';
like $idx, qr/^File:\s+02packages\.details\.txt/m, 'has index header';
like $idx, qr/^Line-Count:   2$/m, 'header line-count matches';
like $idx, qr/^Last-Updated: Thu Jan  1 00:00:00 1970 GMT$/m, 'deterministic date honored';
like $idx, qr/Last-Updated:[^\n]*\n\nTry::Tiny/, 'blank line separates header and body';
like $idx, qr{^Try::Tiny\s+0\.32\s+E/ET/ETHER/Try-Tiny-0\.32\.tar\.gz$}m, 'module row with path';
like $idx, qr{^Try::Tiny::Catch\s+0\.32\s+E/ET/ETHER/Try-Tiny-0\.32\.tar\.gz$}m, 'second module row';
unlike $idx, qr/Not::Locked/, 'module from non-locked dist excluded';

done_testing;
