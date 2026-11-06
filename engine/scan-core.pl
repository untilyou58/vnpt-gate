#!/usr/bin/env perl
# Lõi quét nội dung của VNPTNAN_GATE: áp rule của Gate (rules/gate.rules) và rule nhập từ Gitleaks
# (rules/gitleaks.jsonl/.pldata) trong MỘT tiến trình, thay cho vài chục lệnh grep mỗi file.
# gate-lib.sh gọi; máy không có perl thì gate-lib.sh dùng đường bash cũ.
#
#   perl scan-core.pl [tuỳ chọn] --one <path> <file-dòng> <file-đầy-đủ> <kích-thước>
#   perl scan-core.pl [tuỳ chọn] --list        # stdin: mỗi dòng "kích-thước<TAB>file-dòng<TAB>file-đầy-đủ<TAB>path"
# Tuỳ chọn:
#   --rules F          rules/gate.rules (bỏ trống: không dùng)
#   --gitleaks F       rules/gitleaks.jsonl (bỏ trống: không dùng)
#   --skip RE          regex đường dẫn bỏ qua (SKIP_PATHS, không phân biệt hoa thường)
#   --max-file N       file lớn hơn N byte không quét theo dòng
#   --no-inline-allow  không nhận "gate-allow:<id>" trên dòng (kiểm tra prompt)
# stdout, mỗi phát hiện một dòng:
#   level <TAB> id <TAB> path <TAB> số-dòng <TAB> allowed(0|1) <TAB> dòng-đã-che <TAB> thông-báo
# Chỉ dùng Perl lõi (có sẵn trong Git for Windows và trên Linux).
use strict;
use warnings;
use File::Spec ();

my (%o, @one);
while (@ARGV) {
  my $a = shift @ARGV;
  if    ($a eq '--rules')    { $o{rules} = shift @ARGV }
  elsif ($a eq '--gitleaks') { $o{gl} = shift @ARGV }
  elsif ($a eq '--skip')     { $o{skip} = shift @ARGV }
  elsif ($a eq '--max-file') { $o{max} = shift @ARGV }
  elsif ($a eq '--no-inline-allow') { $o{noinline} = 1 }
  elsif ($a eq '--one')      { @one = splice @ARGV, 0, 4 }
  elsif ($a eq '--list')     { $o{list} = 1 }
  elsif ($a eq '--progress') { $o{progress} = shift @ARGV }   # tổng số file; in tiến độ ra stderr
  else { die "scan-core.pl: tham số lạ $a\n" }
}
my $MAX = $o{max} || 5242880;
my $SKIP = (defined $o{skip} && length $o{skip}) ? qr/$o{skip}/i : undef;

# ---------------------------------------------------------------- rule của Gate
my (@line, @path, @count, @size, @allowre, @exempt);
if ($o{rules} && -f $o{rules}) {
  open my $f, '<:raw', $o{rules} or die "Không mở được $o{rules}: $!\n";
  while (my $l = <$f>) {
    $l =~ s/\r?\n$//;
    next if $l eq '' || $l =~ /^[#@]/;
    my ($id, $level, $kind, $re, $msg) = split /\t/, $l, 5;
    next unless defined $re;
    my $r = { id => $id, level => $level, msg => $msg // '' };
    if ($kind eq 'count' || $kind eq 'size') {
      my ($n, $rx) = split /\|/, $re, 2;
      @$r{qw(n q raw)} = ($n, qr/$rx/i, $rx);
    } else {
      @$r{qw(q raw)} = (qr/$re/i, $re);
    }
    if    ($kind eq 'line')   { push @line, $r }
    elsif ($kind eq 'path')   { push @path, $r }
    elsif ($kind eq 'count')  { push @count, $r }
    elsif ($kind eq 'size')   { push @size, $r }
    elsif ($kind eq 'allow')  { push @allowre, $r->{q} }
    elsif ($kind eq 'exempt') { push @exempt, $r->{q} }
  }
  close $f;
}

# ---------------------------------------------------------------- rule Gitleaks
my (@gl, $glg);
if ($o{gl} && -f $o{gl}) {
  my @objs;
  (my $pld = $o{gl}) =~ s/\.jsonl$/.pldata/;
  if ($pld ne $o{gl} && -f $pld) {
    my $d = do File::Spec->rel2abs($pld);
    die "Không nạp được $pld: " . ($@ || $!) . "\n" unless ref $d eq 'ARRAY';
    @objs = @$d;
  } else {
    require JSON::PP;
    open my $f, '<:raw', $o{gl} or die "Không mở được $o{gl}: $!\n";
    while (my $l = <$f>) { push @objs, JSON::PP::decode_json($l) if $l =~ /\S/ }
    close $f;
  }
  for my $r (@objs) {
    if ($r->{_global}) { $glg = $r->{_global}; compile_allow($glg); next }
    next unless $r->{id};
    $r->{q}  = qr/$r->{re}/   if defined $r->{re};
    $r->{qp} = qr/$r->{path}/ if defined $r->{path};
    compile_allow($_) for @{ $r->{allow} || [] };
    push @gl, $r;
  }
}

sub compile_allow {
  my $a = shift;
  $a->{qre}   = [ map { qr/$_/ } @{ $a->{regexes} || [] } ];
  $a->{qpath} = [ map { qr/$_/ } @{ $a->{paths}   || [] } ];
}

# ---------------------------------------------------------------- tiện ích
sub mask {
  # Như gate_mask: phần khớp dài hơn 8 ký tự thay bằng 6 ký tự đầu + ***; tối đa 72 ký tự.
  my ($text, $secret) = @_;
  if (defined $secret && length($secret) > 8) {
    my $show = substr($secret, 0, 6) . '***';
    $text =~ s/\Q$secret\E/$show/g;
  }
  $text =~ s/^\s+//;
  $text =~ tr/\x00-\x1f\x7f/ /;
  $text = substr($text, 0, 72) . '...' if length($text) > 72;
  return $text;
}

sub entropy {
  my $s = shift; my $n = length $s; return 0 unless $n;
  my %c; $c{$_}++ for split //, $s;
  my $e = 0; for my $k (values %c) { my $f = $k / $n; $e -= $f * log($f) / log(2) }
  return $e;
}

sub gl_allowed {
  my ($a, $path, $secret, $match, $line) = @_;
  my $t = ($a->{target} // '') eq 'match' ? $match : ($a->{target} // '') eq 'line' ? $line : $secret;
  my $re = 0; for (@{ $a->{qre} }) { if ($t =~ $_) { $re = 1; last } }
  my $sw = 0; my $ls = lc $secret; for (@{ $a->{stopwords} || [] }) { if (index($ls, $_) >= 0) { $sw = 1; last } }
  return ($re || $sw) unless $a->{and};
  my @c;
  if (@{ $a->{qpath} }) { my $p = 0; for (@{ $a->{qpath} }) { $p = 1 if $path =~ $_ } push @c, $p }
  push @c, $re if @{ $a->{qre} };
  push @c, $sw if @{ $a->{stopwords} || [] };
  return @c && !grep { !$_ } @c;
}

sub out { print join("\t", @_), "\n" }

sub line_allowed {
  my ($text, $id) = @_;
  return 1 if !$o{noinline} && $text =~ /gate-allow:\Q$id\E(?:[^a-z0-9-]|$)/i;
  for (@allowre) { return 1 if $text =~ $_ }
  return 0;
}

# ---------------------------------------------------------------- quét một file
sub scan_file {
  my ($path, $lines, $full, $size) = @_;
  (my $p = $path) =~ s{\\}{/}g;
  if ($SKIP && $p =~ $SKIP) { $o{nskip}++; return }

  # Rule đường dẫn (trừ file mẫu kind=exempt)
  unless (grep { $p =~ $_ } @exempt) {
    for my $r (@path) { out($r->{level}, $r->{id}, $path, '', 0, '', $r->{msg}) if $p =~ $r->{q} }
  }
  my @glp = grep { !$_->{qp} || $p =~ $_->{qp} } @gl;
  for my $r (grep { !$_->{q} } @glp) { out($r->{level}, $r->{id}, $path, '', 0, '', $r->{desc}) }

  return unless -s $lines;
  open my $lf, '<:raw', $lines or return;
  my $head = ''; read $lf, $head, 8192; seek $lf, 0, 0;
  if (index($head, "\0") >= 0) { close $lf; return }      # file nhị phân: như grep -I
  $size = -s $full unless defined $size && length $size;

  for my $r (@size) {
    out($r->{level}, $r->{id}, $path, '', 0, "$size bytes", $r->{msg}) if $size > $r->{n} && $p =~ $r->{q};
  }
  if ($size > $MAX) { close $lf; return }

  # Rule đếm trên nội dung đầy đủ
  if (@count) {
    my %n;
    if ($full eq $lines) { while (my $l = <$lf>) { for my $r (@count) { $n{ $r->{id} }++ if $l =~ $r->{q} } } seek $lf, 0, 0 }
    elsif (open my $ff, '<:raw', $full) { while (my $l = <$ff>) { for my $r (@count) { $n{ $r->{id} }++ if $l =~ $r->{q} } } close $ff }
    for my $r (@count) {
      my $c = $n{ $r->{id} } || 0;
      out($r->{level}, $r->{id}, $path, '', 0, "$c dòng khớp (ngưỡng $r->{n})", $r->{msg}) if $c >= $r->{n};
    }
  }

  # Rule theo dòng: rule Gate trước, rồi rule Gitleaks cho dòng chưa bị rule secret của Gate bắt
  my $glskip = $glg && grep { $p =~ $_ } @{ $glg->{qpath} };
  my @glc = $glskip ? () : grep { $_->{q} } @glp;
  my (%cap, $ln);
  while (my $l = <$lf>) {
    $ln++;
    $l =~ s/\r?\n$//;
    my $secret_hit = 0;
    for my $r (@line) {
      next if ($cap{ $r->{id} } // 0) >= 20;
      next unless $l =~ $r->{q};
      my $m = $&;
      $cap{ $r->{id} }++;
      $secret_hit = 1 if $r->{id} =~ /^g-secret-/;
      out($r->{level}, $r->{id}, $path, $ln, line_allowed($l, $r->{id}), mask($l, $m), $r->{msg});
    }
    next if $secret_hit || !@glc || length($l) > 20000;
    my $lc = lc $l;
    RULE: for my $r (@glc) {
      if ($r->{kw}) { my $k = 0; for (@{ $r->{kw} }) { if (index($lc, $_) >= 0) { $k = 1; last } } next RULE unless $k }
      next RULE if ($cap{ $r->{id} } // 0) >= 20;
      my $q = $r->{q};
      pos($l) = undef;
      while ($l =~ /$q/g) {
        my $match = $&; my $secret = $match; my $ng = $#+;
        if ($ng >= 1) {
          my @g = map { defined $-[$_] ? substr($l, $-[$_], $+[$_] - $-[$_]) : '' } 1 .. $ng;
          if ($r->{grp}) { next unless $r->{grp} <= $ng; $secret = $g[ $r->{grp} - 1 ] }
          else { for (@g) { if (length) { $secret = $_; last } } }
        }
        pos($l) = $-[0] + 1 if length($match) == 0;
        next if defined $r->{ent} && entropy($secret) <= $r->{ent};
        next if $glg && gl_allowed($glg, $p, $secret, $match, $l);
        my $ok = 0; for (@{ $r->{allow} || [] }) { if (gl_allowed($_, $p, $secret, $match, $l)) { $ok = 1; last } }
        next if $ok;
        $cap{ $r->{id} }++;
        out($r->{level}, $r->{id}, $path, $ln, line_allowed($l, $r->{id}), mask($l, $secret), "$r->{desc} (Gitleaks)");
        next RULE;
      }
    }
  }
  close $lf;
}

if (@one) { scan_file(@one[0, 1, 2, 3]) }
elsif ($o{list}) {
  my $total = $o{progress} || 0;
  my ($done, $last, $width) = (0, 0, 0);
  my $t0 = time;
  my $show = sub {   # một dòng tiến độ, ghi đè bằng \r, tối đa 1 lần/giây
    my ($path) = @_;
    my $pct = $total ? int(100 * $done / $total) : 0;
    my $p = $path // ''; utf8::decode($p);              # cắt theo ký tự, không cắt giữa chữ có dấu
    $p =~ s/^.*(.{40})$/...$1/s;
    my $msg = sprintf "[VNPTNAN_GATE] \x{110}ang qu\x{e9}t %d/%d file (%d%%) %s", $done, $total, $pct, $p;
    my $pad = $width > length($msg) ? ' ' x ($width - length($msg)) : '';
    $width = length $msg;
    my $b = "\r$msg$pad"; utf8::encode($b); print STDERR $b;
  };
  while (my $rec = <STDIN>) {
    $rec =~ s/\r?\n$//;
    my ($size, $lines, $full, $path) = split /\t/, $rec, 4;
    next unless defined $path;
    if ($total && time != $last) { $last = time; $show->($path) }
    scan_file($path, $lines, $full, $size);
    $done++;
  }
  if ($total) {
    print STDERR "\r", ' ' x $width, "\r";
    my $b = sprintf "[VNPTNAN_GATE] \x{110}\x{e3} qu\x{e9}t %d file trong %d gi\x{e2}y; b\x{1ecf} qua %d file theo SKIP_PATHS.\n",
      $done - ($o{nskip} || 0), time - $t0, $o{nskip} || 0;
    utf8::encode($b); print STDERR $b;
  }
}
exit 0;
