#!/usr/bin/python3
"""Container-only MIT KDC/GSSAPI fixture helper. Never log tickets or keytabs."""

import base64
import ctypes as c
import os
from pathlib import Path
import secrets
import subprocess
import sys

REALM = "FIXTURE.INVALID"
DATA = Path("/data/db")


def run(arguments, data=None, expected=0):
    result = subprocess.run(arguments, input=data, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=15, check=False)
    if result.returncode != expected:
        raise ValueError("KDC helper command failed")


def initialize():
    DATA.mkdir(mode=0o700)
    password = secrets.token_hex(32).encode()
    run(["/usr/bin/kdb5_util", "create", "-s", "-r", REALM], password + b"\n" + password + b"\n")
    for principal in ("alice", "static", "HTTP/localhost", "HTTP/wronghost"):
        run(["/usr/bin/kadmin.local", "-q", "addprinc -randkey +requires_preauth " + principal])
        name = principal.replace("/", "-")
        run(["/usr/bin/kadmin.local", "-q", f"ktadd -k {DATA}/{name}.keytab {principal}"])
    os.execv("/usr/bin/krb5kdc", ["krb5kdc", "-n", "-r", REALM, "-P", str(DATA / "kdc.pid")])


def acquire(user):
    cache = "FILE:" + str(DATA / (user + ".ccache"))
    os.environ["KRB5CCNAME"] = cache
    run(["/usr/bin/kinit", "-k", "-t", str(DATA / (user + ".keytab")),
         "-c", cache, user + "@" + REALM])


def token(user, service):
    acquire(user)
    # Bind the installed MIT GSSAPI ABI; all Kerberos/SPNEGO encoding is done by MIT.
    class Buffer(c.Structure):
        _fields_ = [("length", c.c_size_t), ("value", c.c_void_p)]

    class Oid(c.Structure):
        _fields_ = [("length", c.c_uint32), ("elements", c.c_void_p)]

    lib = c.CDLL("libgssapi_krb5.so.2")
    uint = c.c_uint32
    ptr = c.c_void_p
    lib.gss_import_name.argtypes = [c.POINTER(uint), c.POINTER(Buffer), c.POINTER(Oid), c.POINTER(ptr)]
    lib.gss_import_name.restype = uint
    lib.gss_init_sec_context.argtypes = [c.POINTER(uint), ptr, c.POINTER(ptr), ptr,
        c.POINTER(Oid), uint, uint, ptr, c.POINTER(Buffer), ptr, c.POINTER(Buffer), ptr, ptr]
    lib.gss_init_sec_context.restype = uint
    lib.gss_release_buffer.argtypes = [c.POINTER(uint), c.POINTER(Buffer)]
    lib.gss_release_name.argtypes = [c.POINTER(uint), c.POINTER(ptr)]
    lib.gss_delete_sec_context.argtypes = [c.POINTER(uint), c.POINTER(ptr), ptr]
    name_type_bytes = c.create_string_buffer(bytes.fromhex("2a864886f71201020104"))
    mechanism_bytes = c.create_string_buffer(bytes.fromhex("2b0601050502"))
    name_type = Oid(10, c.cast(name_type_bytes, ptr))
    mechanism = Oid(6, c.cast(mechanism_bytes, ptr))
    target_bytes = c.create_string_buffer(("HTTP@" + service).encode("ascii"))
    target = Buffer(len(target_bytes.value), c.cast(target_bytes, ptr))
    minor, name, context = uint(), ptr(), ptr()
    output = Buffer()
    try:
        if lib.gss_import_name(c.byref(minor), c.byref(target), c.byref(name_type), c.byref(name)) != 0:
            raise ValueError("GSS name failed")
        status = lib.gss_init_sec_context(c.byref(minor), None, c.byref(context), name,
            c.byref(mechanism), 2 | 4, 0, None, None, None, c.byref(output), None, None)
        if status not in (0, 1) or not 1 <= output.length <= 32768 or not output.value:
            raise ValueError("GSS initialization failed")
        return base64.b64encode(c.string_at(output.value, output.length))
    finally:
        if output.value:
            lib.gss_release_buffer(c.byref(minor), c.byref(output))
        if context:
            lib.gss_delete_sec_context(c.byref(minor), c.byref(context), None)
        if name:
            lib.gss_release_name(c.byref(minor), c.byref(name))
        run(["/usr/bin/kdestroy", "-c", os.environ["KRB5CCNAME"]])


def main():
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(PATH="/usr/bin:/bin", HOME="/data/db", LANG="C.UTF-8",
                      KRB5_CONFIG="/fixture/krb5.conf", KRB5_KDC_PROFILE="/fixture/kdc.conf")
    args = sys.argv[1:]
    if args == ["start"]:
        initialize()
    elif args == ["ready"]:
        acquire("alice")
        run(["/usr/bin/kdestroy", "-c", os.environ["KRB5CCNAME"]])
    elif args == ["keytab"]:
        data = (DATA / "HTTP-localhost.keytab").read_bytes()
        if not 1 <= len(data) <= 16384:
            raise ValueError("keytab size invalid")
        sys.stdout.buffer.write(base64.b64encode(data))
    elif len(args) == 3 and args[0] == "ticket" and args[1] in ("alice", "static") and args[2] in ("localhost", "wronghost"):
        sys.stdout.buffer.write(token(args[1], args[2]))
    elif args == ["invalid-keytab"]:
        # A ticket cannot be acquired for alice using another principal's key.
        result = subprocess.run(["/usr/bin/kinit", "-k", "-t", str(DATA / "static.keytab"),
            "-c", "FILE:/data/db/invalid.ccache", "alice@" + REALM],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
        if result.returncode == 0:
            raise ValueError("invalid keytab accepted")
    else:
        raise ValueError("invalid helper command")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("KDC helper failed", file=sys.stderr)
        sys.exit(1)
