# The resident redaction agent

`sealkeep agent` is the long-running part of the post-tool hook (`sealkeep guard --after`). It
reads the secret values of the stores one time, keeps them in memory and answers the hook in
milliseconds. Without it, each tool result makes the hook read every store, and a slow store
such as Vault makes that call slow.

The agent does not change which values are redacted. The hook and the agent use the same
`check_output` and the same redactor as `sealkeep run`.

## Start and stop

The hook starts the agent when it is not up. The first tool call after that uses the
in-process path and starts the agent in the background; each later call uses the agent.

```sh
sealkeep agent          # start it now, in the foreground
sealkeep doctor         # show whether it runs and the time of each store
```

`SIGTERM` and `SIGINT` stop the agent, and so does `{"cmd":"stop"}` on its socket. The agent
removes its socket when it stops.

One agent serves one user. If a second `sealkeep agent` starts on the same socket, it sees
the running agent and exits with code 0.

## Sockets and access

The socket is `$XDG_RUNTIME_DIR/sealkeep/agent.sock`. When `XDG_RUNTIME_DIR` is not set, the
folder is `$TMPDIR/sealkeep-<uid>`. The folder has mode 0700 and the socket has mode 0600,
and the agent refuses a folder that another user owns.

Each peer is checked when it connects:

- Linux: `SO_PEERCRED`;
- macOS and the BSDs: `getpeereid`.

A peer with a different uid gets no answer. A platform that cannot report the uid of the
peer refuses every request.

## Protocol

The protocol is one JSON object on each line. One connection carries one request and one
answer.

| Request | Answer |
| --- | --- |
| `{"cmd":"redact","input":<hook input>}` | `{"ok":true,"output":<hook output>}`; `output` is `null` when the result holds no value |
| `{"cmd":"status"}` | `{"ok":true,"status":{…}}` |
| `{"cmd":"reload"}` | `{"ok":true,"status":{…}}` after the new load |
| `{"cmd":"stop"}` | `{"ok":true}`, then the agent exits |

`redact` sends the same JSON that the hook reads on stdin and gets the same JSON that the
hook prints. A result with no secret value gives `output: null`, so the hook prints nothing.

The status holds counts, times and ages only. It never holds a name or a value:

```json
{
  "pid": 1234,
  "socket": "/run/user/1000/sealkeep/agent.sock",
  "started_at": 1762000000,
  "loaded_at": 1762000012,
  "loading": false,
  "values": 42,
  "memlock": true,
  "stores": [
    {"name": "local", "kind": "keyring", "secrets": 40, "list_ms": 3, "get_ms": 11},
    {"name": "vault", "kind": "vault", "secrets": 2, "list_ms": 5960, "get_ms": 18}
  ]
}
```

`list_ms` is the time of the list call of the store, and `get_ms` is the time of all get
calls of that store. `sealkeep doctor` prints these lines as `agent store …`.

## Reload

The agent reads the stores again in these cases:

- `sealkeep set`, `mv`, `rm` and `sync` send `{"cmd":"reload"}` to the socket after they
  change a store;
- a client sends `{"cmd":"reload"}`;
- 10 minutes pass since the last load.

The agent answers the hooks during a load with the old values. It does not block them.

## The hook path and the fallback

The hook sends the tool result with a timeout of 200 ms.

1. The agent answers: the hook prints the redacted result.
2. The socket does not exist: the hook starts the agent in the background, then redacts with
   the in-process path for this call. That path reads the stores in parallel with a limit of
   4 seconds.
3. The agent has the socket but does not answer in 200 ms: the hook redacts with the
   in-process path for this call.

The start marker `agent.start` in the socket folder stops a burst of tool calls from
starting one agent each. A marker older than 15 seconds does not stop a start.

## Memory

The agent keeps the values in memory only. It never writes them to a file or a log, and a
status or an answer holds no value.

The agent does these steps after each load:

- `mlockall(MCL_CURRENT)` to lock its pages in memory;
- a core-dump limit of 0;
- on Linux, `PR_SET_DUMPABLE=0`, so another process cannot read its memory.

A system limit can refuse the lock. The agent then reports `memory locked: no` in
`sealkeep doctor` and continues.

## Cost

The agent removes the store time from each tool call. It does not remove the store time
from the machine: the first load and each reload still take as long as the slowest store.
