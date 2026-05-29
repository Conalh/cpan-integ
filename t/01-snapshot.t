use strict;
use warnings;
use Test::More;
use FindBin ();
use lib "$FindBin::Bin/../lib";
use App::CpanInteg;

my $snap = <<'SNAP';
# carton snapshot format: version 1.0
DISTRIBUTIONS
  Try-Tiny-0.32
    pathname: E/ET/ETHER/Try-Tiny-0.32.tar.gz
    provides:
      Try::Tiny 0.32
  Some-Url-Thing-0.01
    pathname: https://example.com/Some-Url-Thing-0.01.tar.gz
SNAP

my $e = App::CpanInteg::parse_snapshot($snap);
is scalar(@$e), 2, 'parsed two pathnames';
is $e->[0]{basename}, 'Try-Tiny-0.32.tar.gz', 'basename extracted';
ok $e->[0]{cpan},  'standard CPAN path flagged as cpan';
ok !$e->[1]{cpan}, 'url path flagged as non-cpan (unsupported source)';

is_deeply App::CpanInteg::parse_snapshot("no pathnames here\n"), [], 'no pathnames -> empty';

done_testing;
