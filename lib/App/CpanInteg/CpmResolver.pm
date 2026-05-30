package App::CpanInteg::CpmResolver;
use strict;
use warnings;

use App::CpanInteg ();

our $VERSION = '0.001';

# An App::cpm resolver that feeds cpm the SHA-256 pinned in a cpan-integ
# integrity lockfile, so a *patched* cpm verifies each downloaded artifact
# against the lock before unpacking or building it.
#
# It is duck-typed to cpm's resolver interface (a resolve($ctx, $task) method
# returning a hashref) and is loaded via cpm's custom-resolver syntax:
#
#   cpm install --resolver '+App::CpanInteg::CpmResolver,\
#       snapshot=cpanfile.snapshot,integrity=cpanfile.integrity[,mirror=file://.../]' \
#       Module::Name
#
# Resolution is self-contained: it reuses App::CpanInteg's own snapshot and
# lockfile parsers rather than cpm's Resolver::Snapshot / Carton::Snapshot, so
# the only dependency is App::CpanInteg itself. The 'checksum' key it returns is
# inert against stock cpm (which drops it); it only takes effect with the
# in-fetch verification patch (see integration/cpm/).

sub _slurp {
    my ($f) = @_;
    open my $fh, '<', $f or die "CpmResolver: cannot read $f: $!\n";
    local $/;
    return <$fh>;
}

sub new {
    my ($class, $ctx, @args) = @_;
    my %arg = map { my ($k, $v) = split /=/, $_, 2; ($k => $v) } @args;

    my $snapshot_path  = defined $arg{snapshot}  ? $arg{snapshot}  : 'cpanfile.snapshot';
    my $integrity_path = defined $arg{integrity} ? $arg{integrity} : 'cpanfile.integrity';
    -f $snapshot_path  or die "CpmResolver: snapshot not found: $snapshot_path\n";
    -f $integrity_path or die "CpmResolver: integrity lock not found: $integrity_path\n";

    my $snap = App::CpanInteg::parse_snapshot(_slurp($snapshot_path));
    my $lock = App::CpanInteg::parse_lockfile(_slurp($integrity_path));

    # basename (e.g. Try-Tiny-0.32.tar.gz) -> { hash, url, ... }
    my %lock_by_base = map { $_->{basename} => $_ } @$lock;

    # provided package name -> snapshot distribution entry
    my %dist_for_pkg;
    for my $d (@$snap) {
        next unless $d->{cpan};
        for my $p (@{ $d->{provides} || [] }) {
            $dist_for_pkg{ $p->{module} } = $d;
        }
    }

    my $mirror = $arg{mirror};
    $mirror =~ s{/*$}{/} if defined $mirror;

    return bless {
        lock_by_base => \%lock_by_base,
        dist_for_pkg => \%dist_for_pkg,
        mirror       => $mirror,
        integrity    => $integrity_path,
    }, $class;
}

sub resolve {
    my ($self, $ctx, $task) = @_;
    my $package = $task->{package};

    my $d = $self->{dist_for_pkg}{$package}
        or return { error => "no pinned distribution provides $package" };

    my $base = $d->{basename};
    my $le = $self->{lock_by_base}{$base}
        or return { error => "no pinned checksum for $base in $self->{integrity}" };

    my @provides = map { +{ package => $_->{module}, version => $_->{version} } }
        @{ $d->{provides} || [] };
    my ($version) = map { $_->{version} }
        grep { $_->{module} eq $package } @{ $d->{provides} || [] };

    # Default to the pinned download_url (verify real CPAN bytes against the
    # lock); with mirror=, resolve against a local verified mirror instead.
    my $uri = defined $self->{mirror}
        ? $self->{mirror} . "authors/id/" . $d->{pathname}
        : $le->{url};

    return {
        source   => 'cpan',
        distfile => $d->{pathname},
        uri      => $uri,
        version  => (defined $version ? $version : 0),
        provides => \@provides,
        checksum => "sha256:" . $le->{hash},
    };
}

1;
