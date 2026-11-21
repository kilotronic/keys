# keys

A small command-line tool for the owner's credentials that never prints, logs or writes a
credential's value. It reads values from 1Password in memory, passes them only on stdin or in a
child's environment, and prints names, fingerprints, dates and verdicts.

Work in progress: see [What is next](#what-is-next).

## The canary tests

Every command's tests run through one harness, `tests/canary.py`. It plants a made-up value in
a fake 1Password and fake services, runs the command, and fails if the value, or its base64,
hex, URL-encoded or JSON-escaped form, or any 12-character piece of it, appears in:

- stdout or stderr, the command's own streams and the real ones;
- the text of an exception that escapes;
- the argv of any child process (children are fakes on `PATH` that record how they were
  started; a value on stdin is allowed);
- any file under the temporary home, temp directory or working directory, other than files the
  test planted and the command left alone;
- the history of a real interactive `zsh` that ran the command (`canary.shell(...)`).

A hint (the first 8 and last 4 characters) is allowed, since `keys` prints one for keys a
provider issued, as the provider's console does.
