# wolfscp: files and recursive directories

`wolfscp` uses the public wolfSSH SCP client API and the library's default
filesystem callbacks. It has no dependency on BoardSession or Node.js.

```sh
wolfscp -i identity.pem -P 22 file.bin user@host:/tmp/file.bin
wolfscp -r -i identity.pem -P 22 assets user@host:/tmp/assets
wolfscp -r -i identity.pem -P 22 user@host:/tmp/assets assets-copy
```

`-r` enables recursive copying in both directions, including nested and empty
directories and hidden files. It also accepts a regular file. Without `-r`, a
directory source is an error. `-N` selects nonblocking socket operation.

An existing directory destination receives the source basename. A nonexistent
destination names the copied root. Existing same-name directories are merged
and files overwritten; missing parents and file/directory conflicts fail.
Remote paths are quoted as literals: spaces and quotes work, while wildcard,
variable, command and tilde expansion are not performed. NUL/CR/LF and protocol
length limits apply. The default source traversal follows symbolic links;
depth and path-length limits terminate cycles. A failed transfer can leave
partial destination data and does not roll back earlier writes.

## Library interface

Call `wolfSSH_SetScpRecursive(ssh, 1)` on a fresh session before
`wolfSSH_SCP_to(ssh, source, destination)` or
`wolfSSH_SCP_from(ssh, source, destination)`. The default is nonrecursive;
passing zero disables recursion. Configuration after SCP has started is rejected.
The SCP functions create their own Exec channel; do not first open a Shell.

The library owns protocol state, recursive control messages, rekeying, bounded
control-line reads and confirmation handling. Resume the same call after
`WS_WANT_READ`/`WS_WANT_WRITE` (possibly reported through `wolfSSH_get_error()`),
waiting for socket readiness in an event-driven application. All source/destination
strings must remain valid until completion. Download success includes complete
directory nesting and a successful remote exit status.

`wolfSSH_GetScpErrorMsg(ssh)` returns the session-owned error text, or NULL.
Do not free it; copy it before the next SCP operation or session destruction.

Filesystem policy stays in the callbacks. The legacy default receive callback
uses `chdir()` and is suitable for this standalone CLI. Applications sharing a
process working directory should install their own callbacks using
`wolfSSH_SetScpSend/Recv` and per-session contexts. Custom contexts remain owned
by the caller, and receive the unmodified local destination string; default
callback cleanup never casts or frees custom contexts.

The built-in traversal uses `WOLFSSH_SCP_MAX_DEPTH` (default 128) and fixed path
buffers; file sizes are 32-bit (up to 4 GiB minus one byte). No snapshots, locking,
resume, SFTP fallback or preservation of symbolic links is provided.

Windows default callbacks use the C runtime filename encoding, not an explicit
UTF-8 filesystem contract. ASCII filenames are validated on Windows/Wine; paths
not representable in that encoding fail. Applications needing UTF-8 filenames
on Windows should supply wide-path filesystem callbacks. The stdio backend may
have a lower size limit than the 32-bit protocol on some platforms.
