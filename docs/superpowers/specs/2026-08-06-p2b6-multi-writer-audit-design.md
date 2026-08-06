# P2·B6 — multi-writer audit sequencing

**Status:** approved design, spiked against a real filesystem before being written
**Sequenced by:** [docs/ROADMAP.md](../../ROADMAP.md) § B, item B6 — the last
thing standing between this product and a second broker process.
**Covers:** B6 only.
**Deliberately does not cover:** B7 (which this unblocks — see *The plan defect
this found*), B2, B3, and the process model, and therefore § A's exit criterion.
See *What this does not do*.
**Verified against:** ext4 under WSL2, CPython 3.12, four real processes ×
200 appends each. Every number below was measured on that setup, not reasoned
about. The reproduction, the prototype and the three benchmarks are in this
document because each of them changed a decision.

---

## What this is

`AuditLog.append` allocates `(seq, prev_hash)` under a `threading.Lock`. That
lock is process-local. A second process appending to the same log therefore
reads the same head, writes the same `seq`, and chains onto a record that is no
longer the tail.

That is not a hypothetical. Four processes, 200 appends each:

```
today: 800 lines written, 451 distinct seqs, max seq 451
today: verify_chain -> ok=False bad_seq=52
```

800 records, 451 sequence numbers, and the chain reports tampering 52 records
in. The one artifact whose entire pitch is that it can be trusted becomes
unverifiable the moment a second writer exists — and it does so *quietly*,
because the writes themselves all succeed.

This is why one worker is the supported deployment. A2 removed the *budget* as
a reason to run one broker; this is the reason that remained.

---

## The plan defect this found

**B7 is not independent of B6, and the roadmap says it is.**

The roadmap lists B7 (*audit the mint*) as size S and "small and
disproportionately valuable", sequenced as if it could be done in any order.
But the mint does not happen in the broker. It happens in
[control_main.py](../../../warden/broker/control_main.py) — a *separate
process*, deliberately on `backend-net` only, which already shares
`./data:/data` with the broker (see [compose.yml](../../../compose.yml)).

A mint record written into `/data/audit.jsonl` is therefore a second writer
**by construction**. B7 done the obvious way does not merely need B6; it
*creates* the exact bug B6 exists to remove — and in the worst possible shape,
because the control plane writes once per task while the broker writes
constantly, so the corruption would be rare, intermittent, and would present as
tampering.

B7 is size S *after* this document. Before it, it is a way to break the chain.
This is the project's usual failure mode showing up on schedule: the plan was
wrong, the implementations were not.

---

## The seven decisions

### 1 · The head comes from the file's own tail, under an exclusive lock on the file

The roadmap proposed "either a dedicated writer, or move `seq` allocation into
the same store as A2". **Both lose**, and they lose for the same reason: the
chain is *content*-linked, not index-linked. `prev_hash` is the hash of the
previous record's body. Handing out a number is not the hard part.

- **Redis `INCR` for `seq`.** Dead on arrival. Writer A gets 5, writer B gets 6
  — but B needs A's *hash*, which A has not computed yet and may never compute.
- **Redis holds the head; advance it with a CAS.** This is the one that looks
  right and is fatal. Writer A CASes the head from `(5, H5)` to `(6, H6)` and
  is killed before it writes the file. Writer B reads the head, chains record 7
  onto `H6`, and writes. The file now holds record 5 and record 7, and record
  7's `prev_hash` is the hash of a record **whose content nobody has**. The
  chain is broken permanently and *cannot be repaired* — not by replay, not by
  a backup, not by anything, because the missing bytes were never anywhere. A
  design whose crash window destroys the artifact is not a design for an audit
  log.
- **A Redis lock held across the file write.** Recoverable, if the head is
  advanced only after the write returns. It loses on three counts: a network
  round-trip on every append, on the one path that must keep working when
  things are going badly; the classic hold-past-TTL problem, which for a plain
  file cannot be fenced; and a stale-lock recovery path — the hardest code here
  to get right, and the least often executed.
- **A dedicated writer process.** A new single point of failure whose outage
  refuses every call in the system. And to keep B2's durability promise it must
  `fsync` before acknowledging, making every append a synchronous network *and*
  `fsync` round-trip — slower than the ~60 µs local write that B1 and A6 just
  bought.

**`flock(LOCK_EX)` on the file being appended to wins**, and the reasons are
structural rather than aesthetic:

- Its scope is *exactly* the resource. There is no second thing to keep
  consistent with the file, so there is no window in which the two disagree.
- **The kernel releases it when the holder dies.** Every userspace lock —
  Redis, a lockfile, a dedicated writer's queue — needs a stale-lock recovery
  path. This one has none to get wrong.
- It adds no dependency the append path does not already have. A log that can
  only be written when Redis is up is a worse log.

Measured, same four-process load:

```
locked: 800 lines written, 800 distinct seqs, max seq 800
locked: seqs are 1..N dense: True
locked: verify_chain -> ok=True bad_seq=None
```

### 2 · B1's in-memory head cache is removed, not repaired

B1 landed three commits ago for a measured reason and this reverses its
*mechanism*. That needs justifying rather than asserting.

B1's stated goal was "stop re-parsing the file per append" — 0.76 ms at 100
records, 8.0 ms at 1000, 37.1 ms at 4000, all inside the lock every caller
queues on. Reading only the **tail** meets that goal more completely: it never
parses the whole file, not even the once per process the cache still costs.
What B1 got wrong, understandably, since neither A2 nor this existed yet, is
that a cache is a claim about who else is writing.

Warm steady state, at B1's own benchmark points (µs per append):

| existing records | cached (B1) | tail read |
|---|---|---|
| 100 | 53 | 66 |
| 1000 | 51 | 62 |
| 4000 | 62 | 66 |

The tail read costs **~12 µs on a ~60 µs append** and is flat in log size.
Against the pre-B1 baseline it is ~560× faster at 4000 records. Cold, the cache
is worse: a fresh `AuditLog` over 4000 existing records amortises its one full
parse to **294 µs/append** across the next 500 appends, against the tail
reader's 66.

- **Loser: keep the cache and guard it with `os.fstat().st_size` under the
  lock.** Appends only grow the file and nothing in the product truncates it,
  so an unchanged size proves nobody appended. Measured at 49 µs — genuinely
  the fastest option here. It loses because it buys ~12 µs on a ~60 µs append,
  in a component whose call path already contains an HTTP round-trip to OPA, at
  the price of an invariant that has to be defended and mutation-tested. Cheap
  is not the axis this file optimises.
- **Loser: guard it with `mtime` instead.** Rejected outright. `stat` mtime
  granularity is exactly the whole-second hazard that has already bitten this
  project once — CPython's bytecode cache keys on `(mtime in whole seconds,
  size)`, and a same-second edit of equal size silently reran a mutant here.
  A same-second append would be silently missed in precisely the same way.

**Proven, not argued.** One writer reading the tail is not sufficient; the
cache has to go. Interleaving a tail reader and a cache holder against one
file:

```
interleaved tail-reader then cache-holder: verify_chain ok=False bad=3
```

### 3 · The tail window is adaptive, doubling from 4 KiB

Not a taste call. A record is not fixed-width, and its width is not ours to
choose: [proxy.py](../../../warden/broker/proxy.py) takes `authority` straight
off the CONNECT request line — bounded only by asyncio's 64 KiB header limit —
and puts it into the record's `target`. A typical record is 682 bytes; one
with a long host reached 8 665.

A fixed 4 KiB window finds no line boundary inside a record larger than
itself, which means a fixed window fails on exactly the record a *probe*
produces. Measured: a `target.host` of 20 000 characters needs four doublings.

- **Loser: fall back to reading the whole file when the window comes up
  short.** Correct, and it reintroduces the O(n) read that B1 removed — on an
  input the caller chooses. That is a remotely triggerable stall, 37 ms and
  growing, inside the lock every other caller queues on.

**The spike found a bug in this one, which is why it is a decision and not a
detail.** Cutting at the *first* newline in the window is wrong: when the
window lands mid-record, the only newline it contains is the trailing one, and
the cut leaves an empty buffer. It must strip the trailing newline and cut at
the **last** one.

### 4 · Lock acquisition is bounded, and its timeout is an `OSError`

A6 put every append on a 16-thread pool the broker owns. An unbounded
`flock(LOCK_EX)` means one wedged writer wedges every worker, and the broker
stops serving with nothing anywhere saying why.

Bounded with `LOCK_NB` in a spin against a deadline. Measured: gives up at
0.25 s under a held lock, and acquires in under a millisecond once released.

It is raised as an `OSError` **deliberately**, and that is the whole of the
integration: the spine's `except OSError` around every append, its
`AUDIT_UNAVAILABLE_ON_DENY` / `AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED` outcomes,
and [proxy.py](../../../warden/broker/proxy.py)'s best-effort branch already
exist and already do the right thing. A busy log becomes a *recorded refusal*
rather than a hang. This is the same reasoning that made `TaskStateUnavailable`
an `OSError` in A2, and for the same downstream handlers.

- **Loser: unbounded blocking.** A silent, total stall — the failure mode with
  no symptom.
- **Loser: `LOCK_NB` with no retry.** Ordinary contention between two brokers
  would refuse legitimate calls. Contention is the normal case here, not the
  exceptional one.
- **Loser: `SIGALRM`.** Not usable from a threadpool worker at all.

### 5 · A torn trailing line is fatal, and the log is never repaired

A process killed mid-write can leave a partial final line. Appending after it
would produce a chain that can never verify, so the append fails — as an
`OSError`, into the handlers above.

- **Loser: truncate the partial line and carry on.** Never. An audit log that
  silently deletes a byte it did not like is not tamper-evident, and the
  difference between "a writer died here" and "someone edited this" is not a
  distinction this file gets to make on its own.

This matches what the log already does with corruption elsewhere:
`warden verify-chain` reports *chain BROKEN: malformed record* rather than
fixing anything.

### 6 · One chain in one file — not one chain per writer

The alternative is genuinely attractive and was seriously considered: give each
writer its own file and its own `seq` space, and there is no lock to take at
all, no contention, and B1's cache stays valid untouched.

It loses on what it gives up: **the total order**. One chain is what makes
`warden replay <task>` a sequence rather than a bag, and it is what will make
B7's exit criterion — the mint record appears *above* the first tool call —
mean something stronger than "two clocks happened to agree". Per-writer chains
would also need an anchor scheme before an entire writer's history could stop
vanishing undetectably.

**This answers the roadmap's B3 question in the opposite direction from the way
it was posed.** B3 (segment rotation with anchor records) is cheaper *after*
B6, not before. Deriving the head from the file instead of from process memory
is precisely what a rotated segment needs: whoever appends next reads the
anchor record the rotation wrote, and no process is holding a stale idea of the
head that rotation has to invalidate. Doing B3 first would mean two writers
rotating one segment set — strictly worse than two writers on one file.

### 7 · The `threading.Lock` stays, and the `flock` is taken inside it

`flock` alone would be sufficient: two file descriptors in one process do
exclude each other. It stays because in-process contention would otherwise burn
the bounded spin's sleep budget, turning a cheap uncontended mutex into a
5 ms-granularity poll.

One order, always — `threading.Lock`, then `flock`, then the tail read, then
the write. A single pair acquired in a single order, so no deadlock is
constructible.

---

## What changes

`warden/broker/audit.py`, and nothing else. **Zero interfaces change** — the
same lesson A6 recorded: `append()`, `records()` and `verify_chain()` keep
their signatures and their behaviour, so `demo/cli/explain.py`'s `NarratedAudit`
wrapper cannot rot, `warden replay` and `warden verify-chain` are untouched,
and the record body is byte-for-byte identical. `tests/golden/audit-4711.jsonl`
still verifies as 7 records, and `warden-demo explain` still reports 7.

Two existing B1 tests move with the mechanism rather than being deleted:

- `test_appending_does_not_re_read_the_log` gets **stronger**. The property
  ("append never re-reads the whole log") is unchanged, and with no cache to
  populate the *first* append no longer gets an exemption.
- `test_a_failed_write_does_not_advance_the_cached_head` keeps its assertion —
  a failed write must not consume a sequence number — which is now true by
  construction rather than by ordering the cache update after the write. It
  patches `Path.open`, so `append` keeps using `self.path.open(...)`.

---

## Proof table

Every row must be made to **fail** before it counts as passing. A row nothing
has reddened is an intention, not a proof — the A2 spec asserted "a settle
cannot resurrect an evicted task" as passing when nothing tested it.

| # | Claim | Mutation that must redden it |
|---|---|---|
| 1 | Two processes appending to one log produce one dense, intact chain | Remove the `flock` → duplicate seqs, `verify_chain` False |
| 2 | The head is read from the file, not from memory | Reinstate a head cache → interleaved writers break the chain |
| 3 | A record wider than the initial window is still found | Fix the window at 4 KiB → tail read raises on a large `target` |
| 4 | The last *complete* line is the head, not the first boundary | Cut at `find` instead of `rfind` → empty buffer, append fails |
| 5 | A held lock times out rather than hanging | Make the acquire unbounded → the test hangs instead of raising |
| 6 | The timeout is an `OSError`, so the spine refuses and records | Raise a bare `Exception` → the spine 500s instead of refusing |
| 7 | A torn trailing line refuses the append | Skip the malformed-tail guard → an unverifiable chain is extended |
| 8 | `append` never re-reads the whole log | Read `records()` for the head → the call-count assertion fires |
| 9 | A failed write consumes no sequence number | Advance a counter before the write → the next append skips a seq |
| 10 | The record body is unchanged | Any body change → the frozen golden chain stops verifying |

---

## What this does not do

- **`flock` is per-kernel.** Two brokers on two *hosts* sharing one log over a
  network filesystem are **not** covered, and `DEPLOYMENT.md` must say so
  rather than implying multi-writer works everywhere. B5's pluggable sink is
  the answer for that shape, not this.
- **B7 is unblocked, not done.** The control plane still writes no record.
- **§ A's exit still needs a process model that does not exist.** There is no
  `/healthz`, no `/readyz`, no `SO_REUSEPORT`, and
  [`__main__.py`](../../../warden/broker/__main__.py) binds the proxy inside
  the same `asyncio.run` as uvicorn. B6 removes the *audit chain* as the reason
  one worker is the supported deployment; it does not deliver two workers, and
  it does not move ❌ Production. Phase 3 remains the gate.
- **B2 (`fsync`) is untouched.** It composes: the `fsync` belongs inside this
  lock, and the lock is now the obvious place to put it.
