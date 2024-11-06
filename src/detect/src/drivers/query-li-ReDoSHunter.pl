#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Query the shen-ReScue detector for pattern safety
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use IPC::Cmd qw[can_run]; # Check PATH
use JSON::PP; # I/O
use Data::Dumper;
use File::Glob ':glob';
use Carp;


# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $ReDoSHunterDir = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/src/detectors/li-ReDoSHunter";
if (not -d $ReDoSHunterDir) {
  die "Error, could not find ReDoSHunterDir <$ReDoSHunterDir>\n";
}

if (not can_run("java")) {
  die "Error, cannot find 'java'\n";
}

# Check args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 pattern.json\n";
}

my $patternFile = $ARGV[0];
if (not -f $patternFile) {
  die "Error, no such patternFile $patternFile\n";
}

# Read.
my $cont = &readFile("file"=>$patternFile);
my $pattern = decode_json($cont);
my $regex = $pattern->{pattern};

# Write out to a tmp file for ReDoSHunter format.
my $filePath = "$ReDoSHunterDir/data/paper_dataset";
my $fileName = "query-li-ReDoSHunter-$$.txt";
my $tmpFile = "$filePath/$fileName";
unlink $tmpFile;
&writeToFile("file"=>$tmpFile, "contents"=>$regex);
print STDERR "CLEANUP: $tmpFile\n"; # If we time out, the parent can clean up for us.

# Run ReDoSHunter
my $jvmNoDumpFlags = ""; # TODO Is there a portable way to do this? "-XXnoJrDump -XXdumpSize:none"; # Disable crash files (generated if ulimit on memory exceeded).
my $cmdString = "java $jvmNoDumpFlags -jar $ReDoSHunterDir/target/ReDoSHunter-1.0.0.jar $filePath $fileName";
my ($rc, $out) = &cmd("$cmdString 2>&1");
unlink $tmpFile;

# Read results
my $resDir = 'data/expr';
my $result = "";
my ($resFile) = bsd_glob("$resDir/*redos_s_java*");
if ($resFile) {
    $result = &readFile("file"=>$resFile);
} else {
    die "Error: No file found containing 'redos_s_java' in $resDir\n";
}
unlink glob("$resDir/*") or warn "Could not delete files in $resDir: $!";

# Parse to determine opinion
print STDOUT "Result: $result\n";
my $opinion = { };
if ($result =~ m/.*RESULT-TRUE.*/s) {
  $opinion->{canAnalyze} = 1;
  $opinion->{isSafe} = "NO";

  # Capture attack sstrings
  my @attack_strings;
  while ($result =~ /AttackString：(.+?)\s*$/gm) {
      push @attack_strings, $1;  # Capture the attack string content
  }
  $opinion->{evilInput} = \@attack_strings;
} elsif ($result =~ m/.*RESULT-FALSE.*/s) {
  $opinion->{canAnalyze} = 1;
  $opinion->{isSafe} = "YES";
} else {
  $opinion->{canAnalyze} = 0;
  $opinion->{isSafe} = "UNKNOWN";
  $opinion->{evilInput} = ["COULD-NOT-PARSE"];
}

&log("\n\n--------------------\n\nOutput:\n$out");

# Update $pattern.
$pattern->{opinion} = $opinion;

# Emit.
print STDOUT encode_json($pattern) . "\n";

#####################

# input: ($cmd)
# output: ($rc, $out)
sub cmd {
  my ($cmd) = @_;
  &log("CMD: $cmd");
  my $out = `$cmd`;
  return ($? >> 8, $out);
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}

# input: ($exploitString) JSON object
#   fields: separators[] pumps[] suffix
#     separators and pumps have the same length
# output: ($translatedExploitString) hashref
#   fields: pumpPairs[] suffix
#     Each pumpPair is an object with keys: prefix pump
sub translateExploitString {
  my ($es) = @_;

  if (defined($es->{separators}) and defined($es->{pumps}) and defined($es->{suffix})) {
    &log("exploitString looks valid");
  }
  else {
    croak("Invalid exploitString: " . Dumper($es));
  }

  # Convert Weideman's format to something more sensible:
  #   pumpPairs[]
  #   suffix

  my @separators = @{$es->{separators}};
  my @pumps = @{$es->{pumps}};
  if (scalar(@separators) ne scalar(@pumps)) {
    croak("Invalid exploitString: " . Dumper($es));
  }

  my @pumpPairs;
  for (my $i = 0; $i < scalar(@separators); $i++) {
    push @pumpPairs, { "prefix" => $separators[$i],
                       "pump"   => $pumps[$i]
                     };
  }

  my $suffix = $es->{suffix};

  return { "pumpPairs" => \@pumpPairs,
           "suffix"    => $suffix
         };
}

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or confess "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}
