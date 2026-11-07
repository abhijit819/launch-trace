# LaunchTrace — Linux 4.4 startup read recorder

LaunchTrace records a best-effort snapshot of file-backed page-cache READ BIOs
associated with an application's **startup phase**. It does not preload data,
perform pattern aggregation, or build the eventual preloader access pattern.
Those are later userspace/offline stages and are out of scope here.

Target kernel: Linux 4.4, commit
`afd2ff9b7e1b367172f18ba7f693dfb62bdcb2dc`.

## Agreed behavior implemented

- One startup recording per successful-looking exec attempt / original TGID.
- No fork inheritance; child processes do not get a session.
- One pattern per session. A completed pattern is never reopened.
- Recording completes after 2 seconds without a newly recorded page, after
  2 minutes maximum age, when the thread group exits, when STOP is issued, or
  when a configured record cap is reached.
- Completed patterns are retained for 10 minutes from completion.
- `read()` moves a pattern from completed to in-flight. If it is not ACKed,
  it is retried after 30 seconds. ACK removes it immediately.
- Default retained-session limit is 50. The limit can be set before the first
  START and becomes immutable once START has been issued.
- Page records are deduplicated by `(device, inode, page_index)` and sorted by
  starting sector within each device.
- The wire stream uses explicit little-endian fields; native C struct layout
  is not used as the serialization format. The four wire magic bytes are `LTRC`.

## Kernel integration

See `kernel-hooks.patch`. A built-in dispatch layer is required because
built-in kernel code cannot directly call an ordinary loadable-module symbol.
The dispatch layer registers module callbacks and takes a module reference
while a callback is executing.

Copy:

- `launchtrace.h` to `include/linux/launchtrace.h`
- `launchtrace-core.c` to `kernel/launchtrace.c`
- Add `obj-y += launchtrace.o` to `kernel/Makefile`

Then apply/adapt the hook hunks in `kernel-hooks.patch`:

- `fs/exec.c`: `do_execveat_common()` after the `IS_ERR(filename)` check.
- `block/blk-core.c`: `submit_bio()` after `bio->bi_rw |= rw`.
- `kernel/exit.c`: call only when the thread-group `group_dead` condition is
  true. Verify the exact location and identifiers in the complete target tree.

The supplied three source files do not include `kernel/exit.c`, `kernel/Makefile`,
or the full build tree. Therefore the exit hunk and complete integration have
not been verified against the commit. Do not apply the patch blindly.

## Build the module

After the kernel contains the dispatch layer and is rebuilt/booted:

```sh
make KDIR=/path/to/your/linux-4.4/build
sudo insmod launchtrace.ko
```

The module creates `/dev/launchtrace` with mode `0600`. The device must be
opened by the privileged controller/daemon. START/STOP/SET_MAX_APPS require
`CAP_SYS_ADMIN`.

## IOCTLs

Declared in `launchtrace.h`:

| IOCTL | Argument | Meaning |
|---|---|---|
| `LT_IOCTL_SET_MAX_APPS` | pointer to `__u32` | Set retained application-session limit (1–4096), before first START |
| `LT_IOCTL_START` | none | Enable creation of startup sessions |
| `LT_IOCTL_STOP` | none | Stop new sessions and complete all active patterns |
| `LT_IOCTL_ACK` | pointer to `__u64` | ACK the little-endian pattern ID after durable userspace persistence |

The default maximum is 50. Repeated START/STOP cycles are allowed, but the
maximum cannot be changed after the first START.

## read()/poll() behavior

`poll()` reports readable when a completed pattern is available. `read()`
returns exactly one complete serialized pattern. If the supplied buffer is too
small, it returns `-EMSGSIZE` and requeues the pattern. The caller should use a
large buffer; a future version should add chunked reads for very large
patterns. Once recording is stopped and the completed queue is drained,
blocking read returns EOF.

A successful read places the pattern on the in-flight list. If userspace
crashes before ACK, it is offered again after 30 seconds. This is at-least-once
delivery: userspace must make persistence idempotent using `pattern_id`.
The 10-minute retention deadline is not extended by reads or retries.

## Wire format v1

All integers are little-endian. The stream is:

1. `lt_wire_header`
2. `path_len` raw path bytes (no terminating NUL)
3. For each device: `lt_wire_device`
4. For that device: `record_count` instances of `lt_wire_record`

The header contains magic `LTRC`, version, header size, pattern ID,
creation/completion monotonic timestamps in nanoseconds, TGID, completion
reason, path length, device count and total record count. Device records carry
major/minor and record count. Page records carry inode, page index, starting
sector and sector count. Device records are sector-sorted.

ACK passes the same 64-bit little-endian pattern ID found in the wire header.
The IOCTL control arguments (`SET_MAX_APPS`) are native ioctl scalar ABI values;
the serialized stream itself is explicitly little-endian.

## Synchronization and ownership

- `lt_global_lock` protects the session hash, lifecycle lists, configuration,
  retained-session count, state transitions and list ownership.
- Each pattern lock protects its devices, record hash/list, counters and
  activity timestamps.
- The only nested lock order is global lock then pattern lock.
- A lifecycle list owns one `kref`; BIO lookup takes a temporary `kref` before
  dropping the global lock. Moving between lifecycle lists transfers the same
  ownership reference. ACK/expiry drops it. Final release frees records/devices.
- BIO submission never sleeps and does not copy to userspace. `read()` uses a
  mutex and performs serialization/copy without holding spinlocks.
- The built-in dispatch layer uses a module reference around each callback.

## Explicit limitations / not yet verified

1. **Exec failure:** the hook starts capture before exec succeeds. A failed
   exec can create a spurious session. Cleanup/commit-on-success is deferred.
2. **Attribution:** `current->tgid` in `submit_bio()` is best-effort. Deferred
   writeback/worker-context BIOs may not be attributed to the originating app.
3. **Partial BIO vectors:** page-to-sector normalization is approximate. The
   current record stores a full-page sector count and does not correctly model
   partial vectors or multiple fragments. This is deliberately deferred.
4. **Scope:** only file-backed page-cache reads are recorded. Direct I/O,
   anonymous/swap pages, metadata and other special BIOs are not comprehensively
   handled.
5. **Request splitting/remapping:** hook is before generic request processing;
   partition remapping/splitting can change sector interpretation downstream.
6. **Exec path:** placing the hook in `do_execveat_common()` covers native
   execve/execveat and compat wrappers that reach it in this tree, but the
   failed-exec behavior remains as above.
7. **Integration/build:** only `exec.c`, `blk-core.c` and `blk_types.h` were
   supplied. The exact exit hook, kernel build integration, and full Linux 4.4
   compile have not been verified. This package is not compile-tested.
8. **Memory bound:** the implementation caps retained sessions (50 default),
   records per pattern (100,000), and total live records (200,000). These caps
   bound the principal allocations but are not a byte-exact accounting of
   allocator metadata. The record cap is a safety ceiling, not a preload BIO
   request-size limit.
9. **Large read:** one read must fit one serialized pattern; chunking is not
   implemented.
10. **No crash-persistent kernel queue:** patterns survive daemon failure only
    while the kernel module remains loaded and within the 10-minute retention.

This is an experimental implementation for review on a disposable test kernel,
not production-ready code. Compile and stress-test on the exact target tree
before loading it.

## Userspace controller and persistence daemon

The companion userspace implementation is provided in `../LaunchTrace-userspace/`.
Build it with `make`, start `launchtraced daemon` first, then use
`launchtraced set-max-apps N`, `launchtraced start`, and `launchtraced stop`.
The daemon persists each received pattern into an atomic little-endian LTDB
container before issuing the ACK ioctl. See the userspace README for the exact
persistent database format and operational details.
