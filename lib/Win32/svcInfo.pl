use strict;
use warnings;
no warnings qw(uninitialized);
use Win32::Service;
use Win32::SDDL;
use Net::Ping;
$| = 1;

my $p = Net::Ping->new('icmp',2);

open(LOG,">","svcInfo.log") or die("Couldn't open 'svcInfo.log' for writing!\n");
select LOG;
$| = 1;
select STDOUT;

#Edit this line to perform this operation on a list of computers
my @computers = ( $ENV{COMPUTERNAME} );

#Cycle through the list
foreach my $computer(@computers){
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
        Print("SERVICE => $service\n");
        Print("-----------");
        Print("-") for 1..length($service);
        Print("\n\n");

        my $SD = (`sc \\\\$computer sdshow $services{$service}`)[1];
        chomp $SD;
        my $sddl = Win32::SDDL->new('service');
        my $return = $sddl->Import($SD) or die("Unable to import security descriptor '$SD'!\n");
        if($return == 2){
            Print("***EMPTY ACE***\n\n");
            Print("=================================================================\n\n\n");
            next;
        }
        foreach my $ace(sort {$a->{Trustee} cmp $b->{Trustee}} @{$sddl->{ACL}}){
            Print("    Type                  => ".$ace->{Type}."\n");
            Print("    Trustee               => ".$ace->{Trustee}."\n");
            Print("    Access                => ".join("\n                             ",@{$ace->{AccessMask}})."\n");
            Print("    Flags                 => ".join("\n                             ",@{$ace->{Flags}})."\n");
            Print("    Object Type           => ".$ace->{ObjectType}."\n");
            Print("    Inherited Object Type => ".$ace->{InheritedObjectType}."\n");
            Print("\n");
            Print("    ---------------------\n\n");
        }
        Print("=================================================================\n\n\n");
    }
}

sub Print{
    print @_;
    print LOG @_;
}
