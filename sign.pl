#!/usr/bin/perl -w
# Copyright (C) 2022 Dry Ark LLC
# MIT License

use strict;
use Getopt::Long qw/GetOptions/;
use File::Slurp qw/write_file/;
use File::Copy qw/copy/;
use File::Temp qw/tempfile/;
use File::Find qw/find/;

my $app_dir  = "";
my $signer   = "";
my $mp       = "";
my $idchange = "";
GetOptions(
    "signer|s=s"       => \$signer,
    "app|a=s"          => \$app_dir,
    "provision|mp|m=s" => \$mp,
    "idchange|id=s"    => \$idchange
) or die("Error in command line arguments\n");

if( !$app_dir || !$signer ) {
    show_help();
    exit 1;
}

my $copymp = 0;
if( !$mp ) {
    $mp = "$app_dir/embedded.mobileprovision";
} else {
    $copymp = 1;
    print "Overwriting embedded.mobileprovision within app\n";
    copy( $mp, "$app_dir/embedded.mobileprovision" )
}

my $entitlements_file = extract_entitlements( $mp );

if( $idchange ) {
    my $from = "";
    my $to = "";
    if( $idchange =~ m/(.+):(.+)/ ) {
        $from = $1;
        $to = $2;
    } else {
        die "idchange not specified correctly";
    }
    print "=== Updating Bundle IDs for $app_dir ===\n";
    for my $full ( find_files_named( $app_dir, "Info.plist" ) ) {
        my $part = $full;
        $part =~ s/^$app_dir\///;
        $part =~ s/\/Info\.plist$//;
        $part = "App" if( $part eq "Info.plist" );
        
        my $oldid = `/usr/libexec/PlistBuddy -c "print CFBundleIdentifier" "$full"`;
        chomp $oldid;
        if( $oldid =~ m/^$from/ ) {
            my $newid = $oldid;
            $newid =~ s/^$from/$to/;
            print "$part\n";
            print "  To:$newid From:$oldid\n";
            print `/usr/libexec/PlistBuddy -c "set CFBundleIdentifier $newid" "$full"`;
        } else {
            if( $oldid !~ m/^com\.apple\./ ) {
                print "$part\n";
                print "  Kept:$oldid\n";
            }
        }
    }
}

print "=== Signing $app_dir ===\n";
my $xctest = "";
for my $dir ( get_dirs_to_sign( $app_dir ) ) {
    if( $dir =~ m/\.xctest$/ ) {
        $xctest = $dir;
        next;
    }
    if( $dir =~ m/\.appex$/ ) {
        # This makes an assumption that the app extension provisioning profile should
        # be the same as the one used for the entire app. If this is not the case you
        # should replace the mobileprovision files yourself properly before calling
        # this script and not pass the --provision option.
        if( $copymp && -e "$dir/embedded.mobileprovision" ) {
            copy( $mp, "$dir/embedded.mobileprovision" );
        }
        
        # In the case the user has updated the mobileprovision file themselves, the
        # entitlements to use are the ones of it, not of the entire app.
        if( !$copymp ) {
            my $appex_entitlements_file = extract_entitlements( "$dir/embedded.mobileprovision" );
            sign( $dir, $signer, $appex_entitlements_file );
            unlink $appex_entitlements_file;
            next;
        }
    }
    sign( $dir, $signer, $entitlements_file );
}
sign( $xctest, $signer, $entitlements_file ) if( $xctest );
sign( $app_dir, $signer, $entitlements_file );
unlink $entitlements_file;

exit 0;

sub extract_entitlements {
    my $mobile_provision_file = shift;
    my $mobileprovision = `security cms -D -i "$mobile_provision_file"`;
    my ($x,$temp_filename) = tempfile();
    write_file( $temp_filename, $mobileprovision );
    my $entitlements = `/usr/libexec/PlistBuddy -x -c 'print Entitlements' "$temp_filename"`;
    unlink $temp_filename;
    my ($y,$out_filename) = tempfile();
    write_file( $out_filename, $entitlements );
    #print "=== Entitlements ===\n$entitlements\n";
    return $out_filename;
}

sub sign {
    my ( $file, $signer, $efile ) = @_;
    
    #print "Signing $file\n";
    # --continue "Instructs codesign to continue processing path arguments even if processing one fails."
    # The continue flag is used in case there is no "--generate-entitlement-der" in the available codesign binary 
    
    # -f ( force ) is used to directly replace existing signature
    
    my $output = `/usr/bin/codesign --continue --generate-entitlement-der -f -s "$signer" --entitlements "$efile" "$file" 2>&1`;
    $output =~ s|^$app_dir/||s;
    print $output;
}

sub get_dirs_to_sign {
    return collect_files( shift, sub {
        shift; return ( -d && m/\.(appex|framework|dylib|xctest)$/ );
    } );
}

sub find_files_named {
    my ( $path, $tofind ) = @_;
    return collect_files( $path, sub {
        return ( shift eq $tofind );
    } );
}

sub collect_files {
    my ( $path, $condition ) = @_;
    my @files;
    find( {
        wanted => sub { push( @files, $File::Find::name ) if( $condition->( $_ ) ); },
        follow => 1
    }, $path );
    return @files;
}

sub show_help {
    print<<END;
\nUsage: $0 -s signer -a [app folder] [-m file.mobileprovision] [--id com.old:com.new]\n
    -s --signer         CN or SHA1 hash of code signing identity
    -a --app            .app folder to sign
    -m --mp --provision Path to mobileprovision file to use
    --id --idchange     Update bundle id replacing the old prefix with the new\n
END

    print "Available code signing identities:\n";
    print `security find-identity -v -p codesigning`;
}