#!/usr/bin/env python3
"""A fake of the vendor CLIs that sealkeep calls: aws, gcloud, az, op and bw.

It implements the commands of the stores, keeps its state in the JSON file
$FAKE_STATE, and appends each argument list to $FAKE_ARGV_LOG, so a test can check
that no secret value was ever in the arguments of a command. The program name
(argv[0]) selects the CLI.
"""
import base64
import json
import os
import sys

STATE = os.environ["FAKE_STATE"]


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save(s):
    with open(STATE, "w") as f:
        json.dump(s, f)


def opt(args, name, default=None):
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(name + "="):
            return a[len(name) + 1 :]
    return default


def fail(msg, code=1):
    sys.stderr.write(msg + "\n")
    sys.exit(code)


def read_file_arg(v):
    path = v[len("file://") :] if v.startswith("file://") else v
    with open(path) as f:
        return f.read()


def aws(args):
    s = load().setdefault("aws", {})
    cmd = args[1]
    if cmd == "get-secret-value":
        sid = opt(args, "--secret-id")
        if sid not in s:
            fail("An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation", 254)
        print(json.dumps({"Name": sid, "SecretString": s[sid]}))
    elif cmd == "create-secret":
        sid = opt(args, "--name")
        if sid in s:
            fail("An error occurred (ResourceExistsException)", 254)
        s[sid] = read_file_arg(opt(args, "--secret-string"))
        st = load(); st["aws"] = s; save(st)
        print(json.dumps({"Name": sid}))
    elif cmd == "put-secret-value":
        sid = opt(args, "--secret-id")
        if sid not in s:
            fail("An error occurred (ResourceNotFoundException)", 254)
        s[sid] = read_file_arg(opt(args, "--secret-string"))
        st = load(); st["aws"] = s; save(st)
        print(json.dumps({"Name": sid}))
    elif cmd == "list-secrets":
        prefix = opt(args, "--filters").split("Values=", 1)[1]
        print(json.dumps({"SecretList": [{"Name": k, "LastChangedDate": "2026-10-09T00:00:00Z"} for k in sorted(s) if k.startswith(prefix)]}))
    else:
        fail("fake aws: no command " + cmd)


def gcloud(args):
    st = load()
    s = st.setdefault("gcp", {})
    rest = args[1:]
    if rest[0] == "list":
        print(json.dumps([{"name": "projects/1/secrets/" + k, "annotations": v["ann"], "createTime": "2026-10-09T00:00:00Z"} for k, v in sorted(s.items())]))
    elif rest[0] == "describe":
        if rest[1] not in s:
            fail("ERROR: (gcloud.secrets.describe) NOT_FOUND: Secret [x] not found")
        print(json.dumps({"name": rest[1]}))
    elif rest[:3] == ["versions", "access", "latest"]:
        sid = opt(rest, "--secret")
        if sid not in s:
            fail("ERROR: (gcloud.secrets.versions.access) NOT_FOUND: Secret [x] not found")
        sys.stdout.write(s[sid]["value"])
    elif rest[:2] == ["versions", "add"]:
        assert opt(rest, "--data-file") == "-"
        s[rest[2]]["value"] = sys.stdin.read()
        save(st)
    elif rest[0] == "create":
        assert opt(rest, "--data-file") == "-"
        ann = parse_dict(opt(rest, "--annotations"))
        s[rest[1]] = {"value": sys.stdin.read(), "ann": ann}
        save(st)
    elif rest[0] == "update":
        s[rest[1]]["ann"].update(parse_dict(opt(rest, "--update-annotations")))
        save(st)
    elif rest[0] == "delete":
        del s[rest[1]]
        save(st)
    else:
        fail("fake gcloud: no command " + " ".join(rest))


def parse_dict(v):
    if v.startswith("^"):
        delim, body = v[1:].split("^", 1)
    else:
        delim, body = ",", v
    out = {}
    for part in body.split(delim):
        k, val = part.split("=", 1)
        out[k] = val
    return out


def az(args):
    st = load()
    s = st.setdefault("azure", {})
    deleted = st.setdefault("azure_deleted", {})
    cmd = args[2]
    name = opt(args, "--name")
    if cmd == "set":
        if name in deleted:
            fail("(Conflict) Secret is currently in a deleted but recoverable state. Code: ObjectIsDeletedButRecoverable")
        with open(opt(args, "--file")) as f:
            value = f.read()
        i = args.index("--tags")
        tags = {}
        for t in args[i + 1 :]:
            if t.startswith("--"):
                break
            k, v = t.split("=", 1)
            tags[k] = v
        s[name] = {"value": value, "tags": tags}
        save(st)
    elif cmd == "show":
        if name not in s:
            fail("(SecretNotFound) A secret with (name/id) x was not found in this key vault.")
        print(json.dumps({"value": s[name]["value"]}))
    elif cmd == "list":
        print(json.dumps([{"name": k, "tags": v["tags"], "attributes": {"updated": "2026-10-09T00:00:00Z"}} for k, v in sorted(s.items())]))
    elif cmd == "delete":
        if name not in s:
            fail("(SecretNotFound) A secret with (name/id) x was not found in this key vault.")
        deleted[name] = s.pop(name)
        save(st)
    elif cmd == "recover":
        s[name] = deleted.pop(name)
        save(st)
    else:
        fail("fake az: no command " + cmd)


def op(args):
    st = load()
    s = st.setdefault("op", {})
    rest = args
    if rest[:2] == ["item", "get"]:
        title = rest[2]
        for it in s.values():
            if it["title"] == title or it["id"] == title:
                print(json.dumps(it))
                return
        fail('[ERROR] "%s" isn\'t an item in the "x" vault.' % title)
    elif rest[:2] == ["item", "list"]:
        print(json.dumps([{"id": it["id"], "title": it["title"], "updated_at": "2026-10-09T00:00:00Z"} for it in s.values() if "sealkeep" in it.get("tags", [])]))
    elif rest[:2] == ["item", "create"]:
        assert rest[2] == "-"
        it = json.loads(sys.stdin.read())
        it["id"] = "id%d" % (len(s) + 1)
        s[it["id"]] = it
        save(st)
    elif rest[:2] == ["item", "edit"]:
        it = json.loads(sys.stdin.read())
        s[rest[2]] = it
        save(st)
    else:
        fail("fake op: no command " + " ".join(rest))


def bw(args):
    if not os.environ.get("BW_SESSION"):
        fail("Vault is locked.")
    st = load()
    s = st.setdefault("bw", {})
    rest = args
    if rest[:2] == ["list", "items"]:
        q = opt(rest, "--search", "")
        print(json.dumps([it for it in s.values() if q in it["name"]]))
    elif rest[:2] == ["create", "item"]:
        it = json.loads(base64.b64decode(sys.stdin.read()))
        it["id"] = "bw%d" % (len(s) + 1)
        it["revisionDate"] = "2026-10-09T00:00:00Z"
        s[it["id"]] = it
        save(st)
    elif rest[:2] == ["edit", "item"]:
        it = json.loads(base64.b64decode(sys.stdin.read()))
        s[rest[2]] = it
        save(st)
    else:
        fail("fake bw: no command " + " ".join(rest))


def main():
    prog = os.path.basename(sys.argv[0])
    with open(os.environ["FAKE_ARGV_LOG"], "a") as f:
        f.write(json.dumps([prog] + sys.argv[1:]) + "\n")
    args = sys.argv[1:]
    {"aws": aws, "gcloud": gcloud, "az": az, "op": op, "bw": bw}[prog](args)


main()
