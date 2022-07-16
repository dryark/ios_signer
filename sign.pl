#!/usr/bin/perl -w
use strict;
use Getopt::Long qw/GetOptions/;
use File::Slurp qw/write_file/;
use File::Copy qw/copy/;
use File::Temp qw/tempfile/;

my $app = "";
my $signer = "";
my $mp = "";
GetOptions(
  "signer|s=s"       => \$signer,
  "app|a=s"          => \$app,
  "provision|mp|m=s" => \$mp
)
or die("Error in command line arguments\n");

if( !$app || !$signer ) {
    print<<END;
\nUsage: $0 -s signer -a [app folder] [-m file.mobileprovision]\n
  -s --signer         CN or SHA1 hash of code signing identity
  -a --app            .app folder to sign
  -m --mp --provision Path to mobileprovision file to use\n
END

    print "Available code signing identities:\n";
    print `security find-identity -v -p codesigning`;
    exit 1;
}

if( !$mp ) {
    $mp = "$app/embedded.mobileprovision";
}
else {
    print "Overwriting embedded.mobileprovision within app\n";
    copy( $mp, "$app/embedded.mobileprovision" )
}

my $entitlements_file = extract_entitlements( $mp );

my $appfiles = get_dirs( $app );
#print "=== Subcomponents to sign ===\n  ";
#print join( "\n  ", @$appfiles );
#print "\n\n";

print "=== Signing ===\n";
for my $subcomp ( @$appfiles ) {
    sign( $subcomp, $signer, $entitlements_file );
}
sign( $app, $signer, $entitlements_file );
unlink $entitlements_file;

exit 0;

sub extract_entitlements {
    my $mobile_provision_file = shift;
    my $mobileprovision = `security cms -D -i "$mobile_provision_file"`;
    my ($x,$temp_filename) = tempfile();
    write_file( $temp_filename, $mobileprovision );
    my $entitlements = `/usr/libexec/PlistBuddy -x -c 'Print:Entitlements' "$temp_filename"`;
    unlink $temp_filename;
    my ($y,$out_filename) = tempfile();
    write_file( $out_filename, $entitlements );
    print "=== Entitlements ===\n$entitlements\n";
    return $out_filename;
}

sub sign {
    my ( $file, $signer, $efile ) = @_;
    print `/usr/bin/codesign --continue --generate-entitlement-der -f -s "$signer" --entitlements "$efile" "$file"`;
}

sub get_dirs {
    my ( $path, $dirs ) = @_;
    $dirs = [] if( !$dirs );
    my $dh;
    opendir( $dh, $path );
    my @files = readdir( $dh );
    for my $file ( @files ) {
        next if( $file =~ m/^\.+$/ );
        my $full = "$path/$file";
        if( -d $full ) {
            push( @$dirs, $full ) if( $file =~ m/\.(appex|framework|dylib)$/ );
            get_dirs( $full, $dirs );
        }
    }
    closedir( $dh );
    return $dirs;
}