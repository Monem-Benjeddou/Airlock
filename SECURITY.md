<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Airlock contributors -->

# Security policy

Airlock opens files from the internet and talks to your phone, so security reports matter to us.

## Reporting a vulnerability

Please report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a security problem.

Include the Airlock version, your macOS version, and the steps or file that trigger the problem. If a crafted APK, APKS, XAPK or APKM file is involved, attach it to the private report.

We aim to acknowledge reports within 7 days and to publish a fix, with credit if you want it, once users can update.

## In scope

- Anything that lets a file escape the sandboxed parser helper, write outside its job folder, or run code.
- Path traversal, symlinks or decompression bombs that get past the archive checks.
- A safety report that can be made to show a lower risk than the file deserves.
- A change to a phone that happens without the confirmation Airlock promises, or that cannot be restored as described.
- Leaks of file names, package names, device identifiers or your VirusTotal key.

## Supported versions

Only the latest release receives security fixes while Airlock is in preview (0.x).
