#!/usr/bin/perl -w
use strict;
use Getopt::Long qw/GetOptions/;
use File::Slurp qw/write_file/;

my $app = "";
my $signer = "";
GetOptions(
  "signer|s=s" => \$signer,
  "app|a=s"    => \$app
)
or die("Error in command line arguments\n");

if( !$app || !$signer ) {
    print<<END;
\nUsage: $0 -s signer -a [app folder]\n
  -s --signer CN or SHA1 hash of code signing identity
  -a --app    .app folder to sign\n
END

    print "Available code signing identities:\n";
    print `security find-identity -v -p codesigning`;
    exit 1;
}

my $mobileprovision = `security cms -D -i "$app/embedded.mobileprovision"`;
write_file( "./mobileprovision.tmp", $mobileprovision );
my $entitlements = `/usr/libexec/PlistBuddy -x -c 'Print:Entitlements' ./mobileprovision.tmp`;
print "=== Entitlements ===\n$entitlements\n";
write_file( "./entitlements.plist", $entitlements );

my $appfiles = get_dirs( $app );
#print "=== Subcomponents to sign ===\n  ";
#print join( "\n  ", @$appfiles );
#print "\n\n";

print "=== Signing ===\n";
for my $subcomp ( @$appfiles ) {
    sign( $subcomp, $signer );
}
sign( $app, $signer );

sub sign {
    my ( $file, $signer ) = @_;
    print `/usr/bin/codesign --continue --generate-entitlement-der -f -s "$signer" --entitlements "./entitlements.plist" "$file"`;
}

sub get_dirs {
    my ( $path, $dirs ) = @_;
    $dirs = [] if( !$dirs );
    my $dh;
    opendir( $dh, $fullpath );
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