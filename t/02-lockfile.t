use strict;
use warnings;
use Test::More;
use FindBin ();
use lib "$FindBin::Bin/../lib";
use App::CpanInteg;

my $H = 'a' x 64;
my $good = "pkg:cpan/ETHER/Try-Tiny\@0.32 sha256:$H https://cpan.metacpan.org/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz\n";

my $e = App::CpanInteg::parse_lockfile("# header\n\n$good");
is scalar(@$e), 1, 'comments and blank lines skipped; one entry parsed';
is $e->[0]{hash}, $H, 'hash captured (lower-cased)';
is $e->[0]{basename}, 'Try-Tiny-0.32.tar.gz', 'basename derived from url';

eval { App::CpanInteg::parse_lockfile("pkg:cpan/X/Y\@1 sha256:$H\n") };
like $@, qr/malformed lockfile line/, 'too few fields dies';

eval { App::CpanInteg::parse_lockfile("pkg:cpan/X/Y\@1 md5:" . ('a' x 32) . " http://x/Y-1.tar.gz\n") };
like $@, qr/unsupported hash algorithm/, 'md5 rejected (only sha256)';

eval { App::CpanInteg::parse_lockfile("pkg:cpan/X/Y\@1 sha256:abc http://x/Y-1.tar.gz\n") };
like $@, qr/64 hex chars/, 'short sha256 rejected';

eval { App::CpanInteg::parse_lockfile("notapurl sha256:$H http://x/Y-1.tar.gz\n") };
like $@, qr/malformed purl/, 'non-PURL identity rejected';

done_testing;
