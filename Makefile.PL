use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Win32::SDDL',
    AUTHOR              => 'Tim Johnson <tojo2000@tojo2000.com>',
    VERSION_FROM        => 'lib/Win32/SDDL.pm',
    ABSTRACT_FROM       => 'lib/Win32/SDDL.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
	'Win32::OLE' => 0
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Win32-SDDL-*' },
);
