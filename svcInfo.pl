use strict;
use warnings;
no warnings qw(uninitialized);
use Tim::ADSearch;
use Win32::Service;
use Win32::SDDL;
use Net::Ping;
use Data::Dumper;
$| = 1;

my $p = Net::Ping->new('icmp',2);
#my $computers = SearchAD('(objectClass=computer)','sAMAccountName');
my $computers = [];
open(LOG,">>","svcInfo.log") or die("Couldn't open 'svcInfo.log' for writing!\n");
select LOG;
$| = 1;
select STDOUT;
@$computers = ($ENV{COMPUTERNAME});

foreach my $computer(@{$computers}){
    my %services;
    $computer =~ s/\$$//;

    Print("$computer...");

    if($computer =~ /^(\$|\d|\?|\!)/){
        Print("Invalid Name!\n\n");
        next;
    }

    unless($p->ping($computer)){
           Print("No Ping!\n\n");
           next;
    }
    unless(Win32::Service::GetServices("$computer",\%services)){
        Print("Failed!\n\n");
        next;
    }

    Print("\n\n");
    foreach my $service(sort keys %services){
        print "SERVICE => $service\n";
        print "-----------";
        print "-" for 1..length($service);
        print "\n\n";

        my $SD = (`sc \\\\$computer sdshow $services{$service}`)[1];
        chomp $SD;
        my $sddl = Win32::SDDL->new('service');
        my $return = $sddl->Import($SD) or die("Unable to import security descriptor '$SD'!\n");
        if($return == 2){
#            Print("EMPTY ACE!\n\n";
#            Print("\n********************\n\n";
            next;
        }
        foreach my $ace(sort {$a->{Trustee} cmp $b->{Trustee}} @{$sddl->{ACL}}){
            print "    Type                  => ".$ace->{Type}."\n";
            print "    Trustee               => ".$ace->{Trustee}."\n";
            print "    Access                => ".join("\n                             ",@{$ace->{AccessMask}})."\n";
            print "    Flags                 => ".join("\n                             ",@{$ace->{Flags}})."\n";
            print "    Object Type           => ".$ace->{ObjectType}."\n";
            print "    Inherited Object Type => ".$ace->{InheritedObjectType}."\n";
            print "\n";
            print "    ---------------------\n\n";
        }
        print "=================================================================\n\n\n";
    }
}

sub Print{
    print @_;
    print LOG @_;
}
