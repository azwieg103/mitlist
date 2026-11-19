# mitlist

**mitlist** is a read-only command-line listing utility for MIT Kerberos V5. It is intended to provide an `ldaplist`-style view of principals, grouped by principal type and sorted alphabetically.

The project is hosted at [github.com/azwieg103/mitlist](https://github.com/azwieg103/mitlist).

> **Development status:** This README describes the intended interface and package policy. The mitlist implementation and automated release workflows are not yet present.

## What it lists

mitlist will query the MIT Kerberos administration interface and organize principals into these groups:

| Group | Principal form | Display form |
|---|---|---|
| Users | `username@REALM` | `username@REALM` |
| HTTP | `HTTP/hostname@REALM` | `HTTP/hostname@REALM` |
| CIFS | `cifs/hostname@REALM` | `cifs/hostname@REALM` |
| Host | `host/hostname@REALM` | `host/hostname@REALM` |
| IMAP | `imap/hostname@REALM` | `imap/hostname@REALM` |
| SMTP | `smtp/hostname@REALM` | `smtp/hostname@REALM` |
| LDAP | `ldap/hostname@REALM` | `ldap/hostname@REALM` |
| NFS | `nfs/hostname@REALM` | `nfs/hostname@REALM` |

User principals are principals without a service component (a slash). Service principal matching is case-insensitive for the service name. Principals outside the listed groups should be retained in an **Other** group rather than silently discarded.

Each group will be sorted alphabetically by its complete principal name. Groups will be printed in the order shown above, followed by **Other** when needed.

## Intended usage

The goal is a familiar, simple interface:

```bash
# List all principals
mitlist

# List only user principals
mitlist -u

# List a specific service class
mitlist -t HTTP
mitlist -t cifs
mitlist -t host

# Filter principal names
mitlist -f 'www*'

# Select a realm or administrative server
mitlist -r EXAMPLE.COM
mitlist -h kadmin.example.com

# Show help
mitlist --help
```

The final option set will be documented with the implementation. The examples above describe the planned interface and should not be considered available until the corresponding features are implemented.

## Kerberos access

mitlist is intended to use the MIT Kerberos `kadmin` interface to retrieve principal names. It will not read the Kerberos database directly and will not create, modify, or delete principals.

The normal remote-administration authentication mechanisms supported by MIT Kerberos should be used, including an existing Kerberos credential cache or keytab-based authentication where configured. No password should be stored in mitlist configuration or passed on the command line.

The Kerberos administrative ACL must grant the authenticated identity the `list` privilege. mitlist is a listing tool; it does not need principal modification privileges.

## Requirements

- MIT Kerberos V5 client utilities (including `kadmin`)
- A configured Kerberos realm and reachable administration server
- Valid Kerberos credentials with permission to list principals

## Build and installation

The primary packaging target is **AlmaLinux 10 x86_64**. The project will use the same ZWIEGNET RPM release approach as [azwieg103/gnucobol](https://github.com/azwieg103/gnucobol):

- Build in an AlmaLinux 10 environment.
- Produce installable binary RPMs and a source RPM.
- Run build and validation checks before publishing.
- Publish successful packages as GitHub Release assets.
- Increment the ZWIEGNET rebuild number for each published build of the same project version.
- Trigger builds automatically when relevant source or packaging files change, with a manual workflow-dispatch option.

Windows builds are the next priority after the AlmaLinux 10 package. Additional Enterprise Linux and other supported platforms can follow once the primary builds are reliable.

When implemented, local RPM build instructions and package names will be documented here.

## Project goals

1. Provide a concise, predictable listing of MIT Kerberos principals.
2. Separate user principals from common service principals.
3. Sort names alphabetically within each group for easy scanning and comparison.
4. Keep the utility read-only and rely on Kerberos ACLs for access control.
5. Provide repeatable automated builds and downloadable release packages.

## License

The project license will be specified in the source repository.
