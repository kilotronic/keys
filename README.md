# keys

A small command-line tool for the owner's credentials that never prints, logs or writes a
credential's value. It reads values from 1Password in memory, passes them only on stdin or in a
child's environment, and prints names, fingerprints, dates and verdicts.

Work in progress: see [What is next](#what-is-next).

## The canary tests

Every command's tests run through one harness, `tests/canary.py`. It plants a made-up value in
a fake 1Password and fake services, runs the command, and fails if the value reaches:

- stdout or stderr: the command's streams, Python's, and file descriptors 1 and 2, so a child
  that inherits the terminal is caught too;
- the text of an exception that escapes;
- any child process's argv or environment. An audit hook records every child as it starts, and
  any program that is not one of the harness's fakes on `PATH` fails the test. Piping the value
  to a child is allowed only for `op item create` and `op item edit`;
- any file: a write under the temp folder, or outside the temporary home and working folder,
  fails at once; after the run no file there may hold the value unless the test planted it and
  it is unchanged;
- the history of a real interactive `zsh` that ran the command (`canary.shell(...)`), where the
  `keys` process carries the same audit-hook watch.

It looks for the value as sent and in its base64 (any alignment, URL-safe, wrapped), hex, URL
encoded (either case), JSON-escaped, SHA-256, SHA-1 and MD5 forms, any 9-character piece of it,
and any 12-character piece of an encoded form. A hint (the first 8 and last 4 characters) is
allowed only for a value the test marks provider-issued, since `keys` prints one only for keys a
provider issued, as the provider's console does.
