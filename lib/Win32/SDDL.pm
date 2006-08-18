$VERSION = '0.06';

package Win32::SDDL;
use Win32::OLE;

my $CONSTANTS = {};
my $TRUSTEE_CONSTANTS = {};

#Takes a 'Type' argument that modifies the constants
#TODO: Only takes 'service' as a type.
#      Research other types that modify meaning of constants
sub new{
    my $class = shift;
    my $self = {};
    $self->{Type} = shift;
    $self->{SDString} = '';
    $self->{ACL} = {};
    _initialize($self->{Type},$CONSTANTS,$TRUSTEE_CONSTANTS) or die("Unable to initialize Constants!\n");
    bless($self) || die("Unable to bless '$self'!\n");
    return $self;
}

#Imports an SDDL string
sub Import{
    my $self = shift;
    $self->{SDString} = shift;
    my $SDType = $self->{Type};
    my %const = %{$CONSTANTS};
    my %trustees = %{$TRUSTEE_CONSTANTS};
    my @updateConstants = ();
    my $index = 0;
    $self->{ACL} = [];

    #Make sure that it's a valid object.
    unless(ref($self) eq 'Win32::SDDL'){
        die("'$self' is not a valid Win32::SDDL object!\n".ref($self)."\n");
    }

    unless($self->{SDString}){
        return 2;
    }

    #Check that the SDDL string is in a valid format
    my @rights = $self->{SDString} =~ /\((.*?)\)/g;
    unless($self->{SDString}){
        return undef;
    }

    #Cycle through the ACEs
    foreach my $sec(@rights){
        push @{$self->{ACL}},Win32::SDDL::ACE->new($sec,\%trustees,\%const) || die("Unable to parse '$sec' for Win32::SDDL::ACE object creation!\n");
    }
    return 1;
}


#Initializes the constants
sub _initialize{
    my $type = shift;
    $type ||= '';
    my $constants = shift;
    my $trusteeConstants = shift;

    #We only have one valid type at the moment
    if($type and $type ne 'service'){
        warn("Unsupported Type '$type'!\n");
        return 0;
    }

    #Skip this if the hash is already populated
    unless(scalar(keys %{$constants})){
        %{$constants} = (
            #ACE Types
            A  => "ACCESS_ALLOWED",
            D  => "ACCESS_DENIED",
            OA => "ACCESS_ALLOWED_OBJECT",
            OD => "ACCESS_DENIED_OBJECT",
            AU => "SYSTEM_AUDIT",
            AL => "SYSTEM_ALARM",
            OU => "SYSTEM_AUDIT_OBJECT",
            OL => "SYSTEM_ALARM_OBJECT",

            #ACE Flags
            CI => "CONTAINER_INHERIT",
            OI => "OBJECT_INHERIT",
            NP => "NO_PROPAGATE_INHERIT",
            IO => "INHERIT_ONLY",
            ID => "INHERITED",
            SA => "SUCCESSFUL_ACCESS",
            FA => "FAILED_ACCESS",

            #Generic Access Rights
            GA => "GENERIC_ALL",
            GR => "GENERIC_READ",
            GW => "GENERIC_WRITE",
            GX => "GENERIC_EXECUTE",

            #Standard Access Rights
            RC => "READ_CONTROL",
            SD => "DELETE",
            WD => "WRITE_DAC",
            WO => "WRITE_OWNER",

            #Directory Service Object Access Rights
            RP => "DS_READ_PROP",
            WP => "DS_WRITE_PROP",
            CC => "DS_CREATE_CHILD",
            DC => "DS_DELETE_CHILD",
            LC => "DS_LIST",
            SW => "DS_SELF",
            LO => "DS_LIST_OBJECT",
            DT => "DS_DELETE_TREE",

            #File Access Rights
            FA => "FILE_ALL_ACCESS",
            FR => "FILE_GENERIC_READ",
            FW => "FILE_GENERIC_WRITE",
            FX => "FILE_GENERIC_EXECUTE",

            #Registry Access Rights
            KA => "KEY_ALL_ACCESS",
            KR => "KEY_READ",
            KW => "KEY_WRITE",
            KE => "KEY_EXECUTE",

            );

        #Change some constants if the type is service
        if($type eq 'service'){
            $constants->{CC} = "Query Configuration";
            $constants->{DC} = "Change Configuration";
            $constants->{LC} = "Query State";
            $constants->{SW} = "Enumerate Dependencies";
            $constants->{RP} = "Start";
            $constants->{WP} = "Stop";
            $constants->{DT} = "Pause";
            $constants->{LO} = "Interrogate";
            $constants->{CR} = "User Defined";
            $constants->{SD} = "Delete";
            $constants->{RC} = "Read Control";
            $constants->{WD} = "Change Permissions";
            $constants->{WO} = "Change Owner";
        }
    }

    #Skip if the hash has already been populated
    unless(scalar(keys %{$trusteeConstants})){
        %{$trusteeConstants} = (
                    #Trustees
                    AO => "Account Operators",
                    RU => "Pre-Windows 2k Access",
                    AN => "Anonymous Logon",
                    AU => "Authenticated Users",
                    BA => "Built-in Administrators",
                    BG => "Built-in Guests",
                    BO => "Backup Operators",
                    BU => "Built-in Users",
                    CA => "Certificate Server Admins",
                    CG => "Creator Group",
                    CO => "Creator Owner",
                    DA => "Domain Administrators",
                    DC => "Domain Computers",
                    DD => "Domain Controllers",
                    DG => "Domain Guests",
                    DU => "Domain Users",
                    EA => "Enterprise Administrators",
                    ED => "Enterprise Domain Controllers",
                    WD => "Everyone",
                    PA => "Group Policy Administrators",
                    IU => "Interactively Logged-on User",
                    LA => "Local Administrator",
                    LG => "Local Guest",
                    LS => "Local Service Account",
                    SY => "Local System",
                    NU => "Network Logon User",
                    NO => "Network Configuration Operators",
                    NS => "Network Service Account",
                    PO => "Printer Operators",
                    PS => "Personal Self",
                    PU => "Power Users",
                    RS => "RAS Servers Group",
                    RD => "Terminal Server Users",
                    RE => "Replicator",
                    RC => "Restricted Code",
                    SA => "Schema Administrators",
                    SO => "Server Operators",
                    SU => "Service Logon User",
                    CY => "Crypto Operators",
                    IS => "Anonymous Internet Users",
                    MU => "Performance Monitor Users",
                    OW => "Owner Rights SID",
                    RM => "RMS Service"
                   );
    }
    return 1;

}

#Translates the text SID to a readable name.
sub _translateSID{
    my $SID = shift;
    $SID or die("_translateSID() Unable to translate empty SID.");
    my $WMI = Win32::OLE->GetObject("winmgmts:{impersonationLevel=impersonate,(Security)}!\\\\.\\root\\cimv2") or return(0);
    my $obj = $WMI->Get("Win32_SID='".$SID."'");
    unless($obj->{AccountName}){
        return 0;
    }
    return join("\\",($obj->{ReferencedDomainName},$obj->{AccountName}));
}

package Win32::SDDL::ACE;

sub new{
    my $class = shift;
    my $sec = shift;
    my %trustees = %{shift()};
    my %const = %{shift()};
    my $self = {};
        ($self->{Type},$self->{_flags},$self->{_perms},$self->{ObjectType},$self->{InheritedObjectType},$self->{Trustee}) = split(/;/,$sec);

        #Grab each two-letter permission string and translate it if it is a valid constant
        my @perms = $self->{_perms} =~ /\w\w/g or die("Invalid ACE Perms String '$self->{_perms}'!\n");
        foreach my $perm(@perms){
            if($const{$perm}){
                $perm = $const{$perm};
            }
        }
        $self->{AccessMask} = [@perms];

        #Translate the Type (allow, deny, or audit)
        if( my $type = $const{$self->{Type}}){
            $self->{Type} = $type;
        }

        #Translate the ACE flags
        my @flags = ($self->{_flags} =~ /\w\w/g) if $self->{_flags};
        foreach my $flag(@flags){
            if($const{$flag}){
                $flag = $const{$flag};
            }
        }
        $self->{Flags} = [@flags];

        #Translate the SID to a readable name if possible.
        #Cache the results in %trustees
        if($trustees{$self->{Trustee}}){
            $self->{Trustee} = $trustees{$self->{Trustee}};
        }elsif(my $account = Win32::SDDL::_translateSID($self->{Trustee})){
            $trustees{$self->{Trustee}} = $account;
            $self->{Trustee} = $account;
        }
        bless($self) || die("Unable to bless '$self'!\n");
        return $self;
}


1;


=head1 NAME

Win32::SDDL - SDDL parsing module for Windows

=head1 SYNOPSIS

    use Win32::SDDL;

    my $sddl = Win32::SDDL->new( 'service' );

    $sddl->Import( 'D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPLOCRRC;;;PU)' );

    foreach my $mask( @{$sddl->{ACL}} ){
        $trustees{ $mask->{Trustee} } = 1;
    }

    my @trustees = sort keys %trustees;


    print scalar( @{$sddl->{ACL}} )." entries found.\n";


=head1 DESCRIPTION

This module was created to aid in interpreting SDDL strings commonly used in
Windows to represent access control lists.  SDDL stands for Security Descriptor
Definition Language.  Because SDDL uses many predefined constants, it can be
difficult to read.  This module provides an object-oriented interface for
converting and using the information in SDDL strings.

I<NOTE: For resources relating to SDDL, see the SEE ALSO section of this document.>

=head1 METHODS

=over 5

=item Win32::SDDL->new( *type* );

Example:

    my $sddl = Win32::SDDL->new( 'service' );

Creates a new Win32::SDDL object.  Optionally, an object type can be provided.
The only optional type supported at present is 'service'.  This will change
the value of certain constants as they have a different meaning for services
than they do for files, registry keys, or other objects.

=item $sddl->Import( $sddl_string );

Example:

    my $sddl_string = 'D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPLOCRRC;;;PU)';

    $sddl->Import( $sddl_string ) or die( "Error!  Unable to import '$sddl_string'!\n" );

=back

=head1 PROPERTIES

All Win32::SDDL objects have the following properties:

=over 5

=item $sddl->{SDString}

The currently loaded SDDL string

=item $sddl->{Type}

The type of SDDL string (changes the description of some constants).

=item $sddl->{ACL}

An array of Win32::SDDL::ACE objects.

Each object has the following properties:

=over 10

=item Flags

An array of flags translated into English.

=item AccessMask

An array of permissions translated into English.

=item Type

The type of ACE (SYSTEM_AUDIT,ACCESS_ALLOW, or ACCESS_DENY).

=item objectType

A GUID representing the object type for the ACE (usually empty).

=item InheritedObjectType

A GUID representing the parent object type if it exists.

=item Trustee

The Trustee name.

=back

=back

=head1 UPDATE HISTORY

=item See the Changes file.

=head1 BUGS/CHANGES NEEDED

=over 5

=item Replace Win32::OLE Dependency

Right now I'm using WMI to translate SIDs to account names.  I would like to
find a way to import the Win32 API with a minimal footprint to reduce the size
of the module for people who distribute packaged executables and archives of
their scripts.

=item B<Have any questions/suggestions?>

Please contact me if you have any requests or suggestions.

=back

=head1 SEE ALSO

L<http://windowssdk.msdn.microsoft.com/en-us/library/ms723280.aspx>

=head1 COPYRIGHT

Copyright 2006 Tim Johnson

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

Tim Johnson <tojo2000@tojo2000.com>

=cut

