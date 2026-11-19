# mitlist

**mitlist** is a read-only command-line listing utility for MIT Kerberos V5. It provides an `ldaplist`-style view of principals, grouped by principal type and sorted alphabetically.

The project is hosted at [github.com/azwieg103/mitlist](https://github.com/azwieg103/mitlist).

> [!IMPORTANT]
> **KDC ACL CONFIGURATION IS REQUIRED.** The ordinary user principal that runs mitlist must be granted the lowercase **l (list) permission** in the KDC's kadm5.acl file. For example:
>
> ```text
> alice@YOURDOMAIN.COM    l
> ```
>
> Add this on the KDC (not the client), then restart kadmind. Without this ACL entry, mitlist cannot list principals, even when the user has a valid Kerberos ticket. This grants realm-wide name listing only; it does not grant principal or key administration rights. See [Kerberos access: read-only users](#kerberos-access-read-only-users) for exact setup and security scope.

## What it lists

| Group | Principal form |
|---|---|
| Users | `username@REALM` |
| HTTP | `HTTP/hostname@REALM` |
| CIFS | `cifs/hostname@REALM` |
| Host | `host/hostname@REALM` |
| IMAP | `imap/hostname@REALM` |
| SMTP | `smtp/hostname@REALM` |
| LDAP | `ldap/hostname@REALM` |
| NFS | `nfs/hostname@REALM` |

User principals are principals without a service component (a slash). Service names are matched case-insensitively. Other principal types are retained in an **Other** group. Entries are sorted alphabetically within each group.

## Usage

```bash
# List all principals
mitlist

# List only user principals
mitlist -u

# List a service class (case-insensitive)
mitlist -t HTTP
mitlist -t cifs

# Filter principal names
mitlist -f 'www*'

# Restrict to a realm
mitlist -r EXAMPLE.COM

# Show realm and configured KDC/admin servers
mitlist --info

# Help and version
mitlist --help
mitlist --version
```

Options and filters are case-insensitive. The optional positional pattern is equivalent to `--filter`; matching uses case-insensitive shell-style wildcards. `--info` displays the default realm, explicitly configured KDC and admin-server entries, and live DNS SRV answers for KDC UDP/TCP, master KDC UDP/TCP, admin TCP, and password UDP/TCP records. Each answer includes target, port, priority, and weight. This is a DNS lookup, not a connectivity test.

## Kerberos access: read-only users

mitlist uses the MIT Kerberos remote administration protocol to list principal names. It does **not** read the KDC database directly and does not add, modify, delete, or extract keys.

**A normal user does not need an administrative principal such as `andrew/admin@REALM`.** mitlist uses the default credential cache and reads the realm's `admin_server` setting from the active Kerberos configuration (`krb5.conf`, including configuration selected through `KRB5_CONFIG`). It passes that server to `kadmin` and lets MIT Kerberos use the credentials already in the cache; it does not force an `/admin` identity or prompt for a password. The administrator can grant the ordinary principal only the `list` ACL permission.

MIT Kerberos does not provide a general unauthorised principal-enumeration operation. The supported way to allow this read-only listing is the `l` permission in `kadm5.acl`.

### Grant only the list permission

On the primary KDC, as the Kerberos administrator:

1. Find the ACL file configured by `acl_file` in `kdc.conf`. If it is not set, the default is normally `LOCALSTATEDIR/krb5kdc/kadm5.acl` (the exact path depends on how MIT Kerberos was packaged).
2. Back up the ACL file.
3. Add a line for the exact ordinary user principal. For example, in the `YOURDOMAIN.COM` realm:

   ```text
   alice@YOURDOMAIN.COM    l
   ```

4. Put this entry before any broader matching entry that could determine the user's permissions. ACL evaluation is order-sensitive: the first matching entry controls.
5. Restart the administration daemon (`kadmind`) so it reloads the ACL.

The lowercase `l` grants permission to list principals and policies. It does **not** grant permission to add (`a`), modify (`m`), delete (`d`), change passwords (`c`), inquire about individual principal records (`i`), or extract keys (`e`). Do not use `*`, `x`, or `admcil` for this use case.

**Scope note:** MIT Kerberos defines list permission as a database-wide operation; it cannot be limited to a target-principal pattern in the ACL. The user will be able to see principal and policy names throughout the realm, but receives no key material or principal-management rights from this entry alone.

### Verify access

After the KDC administrator has updated the ACL and restarted kadmind, the user should have a valid TGT:

```bash
klist
```

Then test the remote read-only operation using the user's ordinary principal (replace the realm/principal as appropriate):

```bash
kadmin -c "$KRB5CCNAME" -s kdc.yourdomain.com:749 -q list_principals
```

If that succeeds, run:

```bash
mitlist
mitlist -u
mitlist -t HTTP
```

mitlist uses the default credential cache, including KEYRING caches, and obtains the admin server from the active Kerberos configuration for the default realm. It does not prompt for or store a password. The configured admin server's appropriate `kadmin/admin` or `kadmin/ADMINHOST` service principal must be available, and network access to kadmind must be permitted.

If the command fails, check the exact principal shown by `klist`, the ACL entry and its position, the admin-server configuration, kadmind logs, and whether the KDC can issue the kadmin service ticket. A KDC policy rejection while requesting that service ticket is a separate issue from the ACL's `list` authorization; granting broader database privileges will not fix a service-ticket issuance failure.

## Requirements

- MIT Kerberos V5 client utilities (including `kadmin`)
- A configured Kerberos realm and reachable administration server
- A valid Kerberos credential cache
- The authenticated principal's `list` ACL permission on the KDC (required; see the prominent warning above)

## Build and installation

The primary packaging target is **AlmaLinux 10 x86_64**. RPM releases use an automated, repeatable packaging workflow:

- Build in an AlmaLinux 10.
- Produce installable binary RPMs and a source RPM.
- Run build and command-line validation checks before publishing.
- Publish successful packages as GitHub Release assets.
- Increment the RPM release number for each published rebuild of the same project version.
- Trigger builds automatically when relevant source or packaging files change, with a manual workflow-dispatch option.

Windows builds are the next priority after the AlmaLinux 10 package. Additional Enterprise Linux and other supported platforms can follow.

On AlmaLinux 10, install `gcc`, `make`, `krb5-devel`, `krb5-workstation`, and `rpm-build`, then run:

```bash
bash scripts/build-rpm.sh
```

The RPMs are written to `dist/`. The package installs the `mitlist(1)` manual page under the standard man-page directory. GitHub Actions builds and publishes RPM and source RPM assets automatically when relevant files change on `main`.

## Project goals

1. Provide a concise, predictable listing of MIT Kerberos principals.
2. Separate user principals from common service principals.
3. Sort names alphabetically within each group.
4. Keep the utility read-only and rely on Kerberos ACLs for access control.
5. Provide repeatable automated builds and downloadable release packages.

## License

See the repository license file.
