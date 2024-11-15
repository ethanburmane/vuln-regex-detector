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
use Carp;

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $RegulatorDir = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/src/detectors/hong-EvilStrGen";
if (not -d $RegulatorDir) {
  die "Error, could not find RegulatorDir <$RegulatorDir>\n";
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

# Run.
&cmd("cd $ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect 2>&1");
my $cmdString = "./src/detectors/mclaughlin-regulator/fuzzer/build/fuzzer -r '$regex' -l 20 -w 1 --maxtot 1";
my ($rc, $out) = &cmd("$cmdString 2>&1");

# Parse to determine opinion
my $opinion = { };

# Find the total steps
my $regexTotal = 0;
if ($out =~ m/Total=([0-9]+)/) {
  $regexTotal = $1;
}

my $regexMaxObs = 0;
if ($out =~ m/MaxObservation=([0-9]+)/) {
  $regexMaxObs = $1;
}

# Check if Regulator detected ReDoS
if ($regexTotal > 70 || $regexMaxObs > 1) {
  $opinion->{canAnalyze} = 1;
  $opinion->{isSafe} = "NO";

  # Capture attack strings
  my $attackString = "";
  if ($out =~ m/word="([^"]+)"/) {
    $attackString = $1;
  }
  $opinion->{evilInput} = [$attackString];
} elsif ($out =~ m/Regexp compilation failed/) {
  $opinion->{canAnalyze} = 0;
  $opinion->{isSafe} = "UNKNOWN";
  $opinion->{evilInput} = ["COULD-NOT-COMPILE"];
} else {
  $opinion->{canAnalyze} = 1;
  $opinion->{isSafe} = "YES";
  $opinion->{evilInput} = [];
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
