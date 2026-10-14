# Security policy

Vigil is a security plugin, so a flaw in it matters more than in most
plugins. Thank you for taking the time to report one.

## Reporting a vulnerability

Please report privately, not in a public issue or pull request:

- Use GitHub's **Report a vulnerability** button on the
  [Security tab](https://github.com/keasbeexd/omarchy-vigil/security/advisories/new)
  of this repository (private vulnerability reporting).

Include what you found, how to reproduce it, and which version (shown at the
end of the panel's key hints, such as "Vigil 0.30.0", or the commit) you
tested. A proof of concept helps; please do not test against anyone's
machine but your own.

You can expect an acknowledgement within a week. Fixes for confirmed issues
are released as soon as they are ready, with an advisory that credits you
unless you ask not to be named.

## What counts

Anything that breaks the promises in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md), for example:

- something that runs as root without a confirmation card showing the exact
  command, or a card that does not match what runs;
- data from a file, a scan result, a package or plugin name, or the network
  that reaches a shell, a program's arguments or a notification other than
  as the model allows;
- a way for another account or a file planted in your home folder to make
  Vigil write, delete or follow something it should not;
- a way to make Vigil report a machine as safe when one of its checks found
  a problem.

Bugs in the tools Vigil runs (ClamAV, Bumblebee, arch-audit, osv-scanner,
fwupd, pacman, Omarchy) belong to those projects, but tell us too if Vigil
makes one worse.

## Supported versions

Only the latest version on the `master` branch is supported: Omarchy
installs plugins from the default branch and `omarchy-plugin-update` moves
to its newest commit.
