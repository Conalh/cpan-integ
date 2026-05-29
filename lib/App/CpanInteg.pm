package App::CpanInteg;
use strict;
use warnings;

use HTTP::Tiny;
use JSON::PP ();
use Digest::SHA qw(sha256_hex);

our $VERSION = '0.002';

my $API = 'https://fastapi.metacpan.org/v1';

# A standard CPAN author distfile path, e.g. E/ET/ETHER/Try-Tiny-0.32.tar.gz
my $CPAN_PATH = qr{^[A-Z]/[A-Z]{2}/[A-Z0-9][A-Z0-9-]*/[^/]+\.(?:tar\.gz|tgz|tar\.bz2|zip)$};

sub _ua { HTTP::Tiny->new(agent => "cpan-integ/$VERSION ", timeout => 60) }

# ---------------------------------------------------------------------------
# command dispatch
# ---------------------------------------------------------------------------
sub run {
    my ($class, @argv) = @_;
    my $cmd = shift @argv;
    $cmd = 'help' unless defined $cmd;

    return cmd_pin(@argv)    if $cmd eq 'pin';
    return cmd_verify(@argv) if $cmd eq 'verify';
    return cmd_help()        if $cmd =~ /^(?:help|--help|-h)$/;

    warn "cpan-integ: unknown command '$cmd'\n\n";
    cmd_help();
    return 2;
}

sub cmd_help {
    print <<"USAGE";
cpan-integ $VERSION — consumer-side integrity verification for CPAN installs

Records the SHA-256 of each resolved distribution's actual bytes in a committed
lockfile, then fails if a fetched artifact does not match. Trust model:
trust-on-first-pin (locally hashed bytes), cryptographically verified after.

Usage:
  cpan-integ pin    [--snapshot cpanfile.snapshot] [--out cpanfile.integrity]
                    [--allow-nonstandard]
  cpan-integ verify [--integrity cpanfile.integrity] [--snapshot cpanfile.snapshot]
                    [--allow-nonstandard]

  pin     Download each distribution in a cpanfile.snapshot, hash the bytes
          locally, cross-check against MetaCPAN's published checksum, and write
          a PURL-keyed lockfile. Aborts if any local/MetaCPAN hash disagrees.
  verify  Re-fetch each pinned artifact and fail on SHA-256 mismatch. With
          --snapshot, also fail if the lock and snapshot do not describe the
          same set of CPAN artifacts.
USAGE
    return 0;
}

# ---------------------------------------------------------------------------
# pure helpers (no I/O — unit tested in t/)
# ---------------------------------------------------------------------------

# Parse cpanfile.snapshot text -> arrayref of
#   { pathname, basename, cpan => 0|1 }
sub parse_snapshot {
    my ($text) = @_;
    my @entries;
    for my $line (split /\n/, $text) {
        next unless $line =~ /^\s*pathname:\s*(\S+)/;
        my $pathname = $1;
        my ($basename) = $pathname =~ m{([^/]+)\z};
        push @entries, {
            pathname => $pathname,
            basename => $basename,
            cpan     => ($pathname =~ $CPAN_PATH ? 1 : 0),
        };
    }
    return \@entries;
}

# Parse lockfile text -> arrayref of { purl, algo, hash, url, basename }.
# Dies on any malformed / unsupported line.
sub parse_lockfile {
    my ($text) = @_;
    my @entries;
    my $lineno = 0;
    for my $line (split /\n/, $text) {
        $lineno++;
        next if $line =~ /^\s*#/ || $line =~ /^\s*\z/;
        my @f = split ' ', $line;
        die "cpan-integ: malformed lockfile line $lineno: expected '<purl> <algo>:<hex> <url>'\n"
            unless @f == 3;
        my ($purl, $digest, $url) = @f;
        die "cpan-integ: malformed purl on line $lineno: '$purl'\n"
            unless $purl =~ m{^pkg:cpan/\S+\@\S+\z};
        my ($algo, $hex) = $digest =~ /^([a-z0-9]+):([0-9a-fA-F]+)\z/
            or die "cpan-integ: malformed digest on line $lineno: '$digest'\n";
        die "cpan-integ: unsupported hash algorithm '$algo' on line $lineno (only sha256)\n"
            unless $algo eq 'sha256';
        die "cpan-integ: sha256 must be 64 hex chars on line $lineno\n"
            unless length($hex) == 64;
        my ($basename) = $url =~ m{([^/]+)\z};
        push @entries, {
            purl => $purl, algo => $algo, hash => lc $hex, url => $url, basename => $basename,
        };
    }
    return \@entries;
}

# Cross-check that the lock constrains exactly the CPAN artifacts in the
# snapshot. Returns a list of problem strings (empty list = consistent).
sub reconcile {
    my ($snap, $lock, %opt) = @_;
    my @problems;

    unless ($opt{allow_nonstandard}) {
        push @problems, "non-CPAN source not allowed (use --allow-nonstandard): $_->{pathname}"
            for grep { !$_->{cpan} } @$snap;
    }

    my %in_snap = map { $_->{basename} => 1 } grep { $_->{cpan} } @$snap;
    my %in_lock = map { $_->{basename} => 1 } @$lock;

    push @problems, "snapshot distribution missing from integrity lock: $_"
        for grep { !$in_lock{$_} } sort keys %in_snap;
    push @problems, "integrity lock entry not present in snapshot: $_"
        for grep { !$in_snap{$_} } sort keys %in_lock;

    return @problems;
}

# "E/ET/ETHER/Try-Tiny-0.32.tar.gz" -> ("ETHER", "Try-Tiny-0.32")
sub _author_release {
    my ($path) = @_;
    my @seg    = split m{/}, $path;
    my $author = $seg[-2];
    (my $name = $seg[-1]) =~ s/\.(?:tar\.gz|tar\.bz2|tgz|zip)\z//;
    return ($author, $name);
}

# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------
sub _slurp {
    my ($f) = @_;
    open my $fh, '<', $f or die "cpan-integ: cannot read $f: $!\n";
    local $/;
    return <$fh>;
}

sub _parse_argv {
    my ($defaults, @argv) = @_;
    my %o = %$defaults;
    while (@argv) {
        my $a = shift @argv;
        $a =~ /^--(\w[\w-]*)\z/ or die "cpan-integ: unexpected argument '$a'\n";
        (my $k = $1) =~ tr/-/_/;
        if ($k eq 'allow_nonstandard') { $o{$k} = 1 }     # boolean flag
        else                           { $o{$k} = shift @argv }
    }
    return %o;
}

# The /release/{author}/{name} endpoint wraps the object in a "release" key;
# /release/{dist} returns it bare. Unwrap either shape.
sub _release_meta {
    my ($ua, $author, $name) = @_;
    my $res = $ua->get("$API/release/$author/$name");
    return undef unless $res->{success};
    my $data = eval { JSON::PP->new->decode($res->{content}) };
    return undef unless $data;
    my $rel = (ref $data eq 'HASH' && ref $data->{release} eq 'HASH') ? $data->{release} : $data;
    return (ref $rel eq 'HASH' && $rel->{download_url}) ? $rel : undef;
}

# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
sub cmd_pin {
    my %o = _parse_argv(
        { snapshot => 'cpanfile.snapshot', out => 'cpanfile.integrity', allow_nonstandard => 0 },
        @_,
    );

    -e $o{snapshot} or die "cpan-integ: snapshot not found: $o{snapshot}\n";
    my $snap = parse_snapshot(_slurp($o{snapshot}));
    @$snap or die "cpan-integ: no distributions found in $o{snapshot}\n";

    my $ua = _ua();
    my @lines;
    my ($pinned, $failed) = (0, 0);

    for my $e (@$snap) {
        unless ($e->{cpan}) {
            if ($o{allow_nonstandard}) { warn "  skipping non-CPAN source: $e->{pathname}\n"; next }
            die "cpan-integ: non-CPAN source in snapshot (use --allow-nonstandard to skip): $e->{pathname}\n";
        }

        my ($author, $name) = _author_release($e->{pathname});
        my $rel = _release_meta($ua, $author, $name);
        unless ($rel) {
            warn "cpan-integ: no MetaCPAN release metadata for $e->{pathname}\n";
            $failed++;
            next;
        }

        # Download the actual artifact and hash the bytes locally.
        my $res = $ua->get($rel->{download_url});
        unless ($res->{success}) {
            warn "cpan-integ: download failed for $rel->{download_url}: $res->{status} $res->{reason}\n";
            $failed++;
            next;
        }
        my $local = lc sha256_hex($res->{content});

        # Cross-check against MetaCPAN's published checksum when available.
        if (my $mc = $rel->{checksum_sha256}) {
            if (lc($mc) ne $local) {
                warn "cpan-integ: PIN ABORTED — hash disagreement for $e->{basename}\n"
                   . "    local sha256    $local\n"
                   . "    MetaCPAN sha256 " . lc($mc) . "\n";
                $failed++;
                next;
            }
        }
        else {
            warn "  note: MetaCPAN published no checksum to cross-check for $e->{basename}\n";
        }

        my $purl = sprintf 'pkg:cpan/%s/%s@%s',
            uc($rel->{author}), $rel->{distribution}, $rel->{version};
        push @lines, sprintf '%s sha256:%s %s', $purl, $local, $rel->{download_url};
        warn "  pinned $purl\n";
        $pinned++;
    }

    die "cpan-integ: pin aborted — $failed distribution(s) could not be pinned safely\n"
        if $failed;

    open my $fh, '>', $o{out} or die "cpan-integ: cannot write $o{out}: $!\n";
    print {$fh} "# cpanfile.integrity - generated by cpan-integ $VERSION\n";
    print {$fh} "# format: <purl> sha256:<hex of locally-hashed bytes> <download_url>\n";
    print {$fh} "$_\n" for @lines;
    close $fh;

    print "cpan-integ: pinned $pinned distribution(s) to $o{out}\n";
    return 0;
}

sub cmd_verify {
    my %o = _parse_argv(
        { integrity => 'cpanfile.integrity', snapshot => undef, allow_nonstandard => 0 },
        @_,
    );

    -e $o{integrity} or die "cpan-integ: integrity file not found: $o{integrity}\n";
    my $lock = parse_lockfile(_slurp($o{integrity}));    # dies on malformed input

    # Phase 1: constrain the lock to the snapshot, if one is supplied.
    if (defined $o{snapshot}) {
        -e $o{snapshot} or die "cpan-integ: snapshot not found: $o{snapshot}\n";
        my $snap = parse_snapshot(_slurp($o{snapshot}));
        my @problems = reconcile($snap, $lock, allow_nonstandard => $o{allow_nonstandard});
        if (@problems) {
            print "FAIL  snapshot/lock consistency:\n";
            print "        - $_\n" for @problems;
            printf "\ncpan-integ: consistency check failed (%d problem(s))\n", scalar @problems;
            return 1;
        }
        printf "ok    snapshot/lock consistency (%d entries)\n", scalar @$lock;
    }

    my $ua = _ua();
    my ($ok, $fail) = (0, 0);
    for my $e (@$lock) {
        my $res = $ua->get($e->{url});
        unless ($res->{success}) {
            printf "FAIL  %s  (download error: %s %s)\n", $e->{purl}, $res->{status}, $res->{reason};
            $fail++;
            next;
        }
        my $got = lc sha256_hex($res->{content});
        if ($got eq $e->{hash}) {
            printf "ok    %s\n", $e->{purl};
            $ok++;
        }
        else {
            printf "FAIL  %s\n        expected %s\n        got      %s\n", $e->{purl}, $e->{hash}, $got;
            $fail++;
        }
    }
    printf "\ncpan-integ: %d verified, %d failed, %d total\n", $ok, $fail, scalar @$lock;
    return $fail ? 1 : 0;
}

1;
