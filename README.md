Fend — This sandbox guards all access to all files by a program. If an access is disallowed the offending system call will return the EACESS error code.

#Invocation:

<b>fend [-c config] <command [args ...]> </b>
where config is an optional configuration file and command is the program the is being sandboxed. If the config file option is not given, the program will look for a file named .fendrc first in the current working directory and second in the user's home directory. If none are found, exit with the message "Must provide a config file."
<b>Fend is more restrictive then the OS. It will not permit accesses that the OS prohibits. </b>

#Configuration file

The configuration file contains one specification per line. Each specification contains a permission and one glob pattern (see wiki and glob(3) man page). The fields are separated by any number of spaces or tabs. The permission is a 3-bit binary digit, representing in order read, write, and execute permissions. See chmod(1) man page. Therefore,

111 foo.txt is full permission and
000 foo.txt is complete denial.
It is possible that more than one specification matches a given file name. <b>In such a case, the last match is the one that holds.</b> For example, suppose the following two-line configuration file.

000 /usr/foo/*
110 /usr/foo/bar

The file "/usr/foo/bar" matches both lines. Therefore, the last line (110) holds. This is useful for denying access to all files in directory except for an enumerated few.

File names presented to the guarded system calls are generally absolute paths. Therefore, globs based on relative paths names (such as "foo" or "../bar") will not work as you may think. Globs, however, do not need to be absolute paths. For example the glob "*/foo" refers to every file named foo regardless of which directory contains it.

No Implicit Restrictions

If no specification matches the file name, then fend will not restrict the access. If you would like fend to restrict access to all files then include the specification:
000 * at the top of the config file.
