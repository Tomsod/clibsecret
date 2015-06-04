clibsecret
==========

This is a command-line tool to manipulate passwords stored in [GNOME Keyring](https://wiki.gnome.org/Projects/GnomeKeyring)
as well as any other service implementing Secret Service D-Bus API.
This particular program is focused on full API coverage and convenient batch-processing.

Here's an example:
    clibsecret foo bar --info '%i %A %v ' | sed 's/\bbar\b/baz/' | clibsecret --read '%i %A %v '
This command searches for all passwords with tag foo=bar and changes it to baz. (\b stands for word boundary, if you're curious.)  
For more info, see supplied man page.
