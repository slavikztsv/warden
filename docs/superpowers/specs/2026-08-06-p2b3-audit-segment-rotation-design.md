# P2 § B3 — segment rotation that a chain survives

Design, 2026-08-06. ROADMAP § B, item B3: *"Segment rotation with an anchor
record carrying the previous segment's head hash, so a rotated chain still
verifies end to end."* Size M. B4 (*teach `warden verify-chain` about
segments*) follows directly and is deliberately not this.

## The problem, and the one question that decides it

The audit log is one file that only grows. B1 and B6 made *appending* to it
constant-time; nothing bounds its size. A million decisions is a ~550 MB
single-line-per-record file that `records()` loads whole into memory, that no
editor opens, and that an operator can neither archive nor ship anywhere in
parts.

Rotation is the obvious answer and it is a *chain* problem, not a file
problem. The chain is content-linked: record N+1 carries `prev_hash =
hash(N)`. Split the file and the link has to survive the split, in both
directions — the writer must not lose track of where the chain is, and the
reader must be able to put the pieces back in order and say so when a piece
is missing.

The handover named the load-bearing question:

> Does `_head_from_tail` still answer correctly across a segment boundary? A
> fresh segment's tail read returns `(0, GENESIS_HASH)` for an empty file —
> which is exactly wrong after rotation, because the next record must link to
> the previous segment's head, not to genesis. Spike it before speccing.

It was spiked. The answer is **no, and the failure is silent** — and it is
silent in the most expensive possible way.

```
=== Q1: naive rotation, rename then let the writer recreate ===
  closed segment head: seq=3 hash=3537fcabd216
  next record written: seq=1 prev_hash=000000000000
  _head_from_tail on the fresh file said genesis: True
  active file now holds 1 record(s), and the log has TWO records numbered 1..3 and 1
```

Rename the active file away and let the next `append()` recreate it — which
`"a+b"` does, silently — and the log restarts at seq 1 from genesis. Every
record still verifies. `verify_chain()` over the active file returns
`(True, None)`. The log now contains two chains, both internally perfect, and
nothing anywhere says so.

So the whole design follows from one invariant:

> **The name in `[audit].path` must never, at any instant, refer to an empty
> file once the log has a history.**

Everything below is that invariant plus what it takes to hold it while two
processes write (B6) and while the host can lose power at any point (B2).

## What the spike measured

Prototype in `scratchpad/spike/proto.py`, a copy of `audit.py` with rotation
added and a switch to disable the staleness check. Records here average
**547 bytes** (`target = {"kind": "doc"}`; the B2 spec's 682-byte typical
record has a fuller target — both are in range).

### 1. The per-append cost of the checks — interleaved, 400 samples each

Round-robin between three logs in one process, so drift and thermal state
cancel. A separately-timed `os.fstat` is 0.96 µs here and `os.stat` is
2.08 µs.

| durability | variant | median | delta |
|---|---|---|---|
| flush | shipped `audit.py` | 68.4 µs | — |
| flush | rotation, `segment_bytes = 0` | 75.1 µs | +6.7 µs (1.10×) |
| flush | rotation, `segment_bytes = 64 MiB` | 75.7 µs | +7.3 µs (1.11×) |
| fsync | shipped `audit.py` | 1885.9 µs | — |
| fsync | rotation, `segment_bytes = 0` | 1878.7 µs | −7.1 µs (1.00×) |
| fsync | rotation, `segment_bytes = 64 MiB` | 1865.6 µs | −20.3 µs (0.99×) |

Two decisions fell out. `segment_bytes = 0` and `= 64 MiB` are
indistinguishable (75.1 against 75.7), so **the size check is free** and does
not need to be conditional on rotation being enabled. And at the shipped
default durability the whole thing is inside the noise — ±20 µs on 1886 —
so **the checks do not need to be gated on anything**; a first draft had them
skipped when `segment_bytes == 0`, which would have made a correctness check
depend on a config value.

### 2. What rotation costs, and how often

| durability | plain append | the append that rotates |
|---|---|---|
| flush | 84.3 µs | 381.5 µs |
| fsync | 1892.6 µs | 5398.9 µs |

Rotation adds ~300 µs at `flush` and ~3.5 ms at `fsync` (one fsync for the
staging file, one for the directory — the same two B2 measured at 1.7 ms and
1.4 ms). It happens once per segment: at 547 bytes a record, a 64 MiB segment
is **~123,000 records**, so the amortised cost is 0.03 µs per append. Nothing.

These are the prototype's numbers, taken *before* the review added a second
directory fsync (decision 17), which should put a rotating `fsync` append near
6.8 ms. The implementation re-measures rather than inheriting the estimate.

| segment | records at 547 b | segments per million records |
|---|---|---|
| 16 MiB | 30,727 | 33 |
| 64 MiB | 122,910 | 8 |
| 256 MiB | 491,640 | 2 |

### 3. Reading across segments

| layout | records | segments | `records()` median | verify |
|---|---|---|---|---|
| one file | 3000 | 1 | 24.41 ms | ok |
| 64 KiB segments | 3025 | 26 | 25.14 ms | ok |

3 % for 26 segments — about 27 µs per segment, the cost of an open and a
first-line read. **The segment list does not need caching**, which was the
other thing a first draft was going to add.

### 4. The one that matters — concurrent rotation, with and without the check

Four processes, 40 appends each, `segment_bytes = 4096` (so a segment holds
~8 records and rotation is violently frequent), three runs each. `LOST` counts
records whose `append()` **returned successfully** and which are not reachable
from the active file afterwards.

```
  --- NO staleness check ---
  run 1: returned= 75 dead=3 on-disk= 65 reachable= 65 LOST=  0 segments= 9  verify ok=False bad=33
  run 2: returned= 54 dead=3 on-disk= 43 reachable= 29 LOST= 14 segments= 4  UNREADABLE: audit log has segment files nothing in the chain names: ['audit-000032.jsonl', 'audit-000040.jsonl']
  run 3: returned= 35 dead=4 on-disk= 29 reachable= 15 LOST= 14 segments= 2  UNREADABLE: audit log has segment files nothing in the chain names: ['audit-000016.jsonl', 'audit-000024.jsonl']

  --- WITH staleness check ---
  run 1: returned=160 dead=0 on-disk=160 reachable=160 LOST=  0 segments=23  verify ok=True bad=None
  run 2: returned=160 dead=0 on-disk=160 reachable=160 LOST=  0 segments=23  verify ok=True bad=None
  run 3: returned=160 dead=0 on-disk=160 reachable=160 LOST=  0 segments=23  verify ok=True bad=None
```

Three of four writers died every run; between 35 and 75 of 160 appends
returned at all; and what survived was either a chain **BROKEN at seq 33** or
a log that **refuses to be read**. This is B6's failure mode arriving through
a new door: writes succeed, the chain does not.

The mechanism is worth stating precisely, because it is not the one this design
first predicted. A writer opens `[audit].path`, then spins for the `flock`.
Another writer holding that lock rotates. The first writer now holds a
descriptor on the *closed* segment, and its size is still over the threshold —
so it does not merely append into a closed file, it tries to **rotate it
again**, producing a second, divergent lineage of segments. The prediction was
one stray record in a closed segment; the reality is a forked segment tree.

## The design

### Naming

The active segment keeps `[audit].path`, forever. Closed segments are
siblings named `<stem>-<last seq, 6 digits><suffix>`:

```
/data/audit.jsonl            the active segment — always
/data/audit-000008.jsonl     records 1..8
/data/audit-000016.jsonl     records 9..16
```

The number is the `seq` of the segment's **last** record, which the tail read
already has in hand at rotation time, so naming costs no extra read. It is
unique by construction (seqs are), it sorts correctly up to 999,999 segments,
and past that it grows a seventh digit and sorts wrong — which costs nothing,
because ordering comes from the anchors and not from the filenames.

### The anchor

The first record of every segment after the first is an **anchor**: an
ordinary record, thirteen body fields, `action.type = "anchor"`.

```json
{"action":{"type":"anchor"},"agent_id":"warden","args_digest":"none",
 "decision":"none","policy_bundle_digest":"none","prev_hash":"<closing head>",
 "purpose":"audit-segment-rotation","rule":"audit.rotation","seq":9,
 "target":{"kind":"segment","previous":"audit-000008.jsonl"},
 "task_id":"-","task_state":{"data_classes_held":[],"rows_charged_so_far":0},
 "ts":"...","hash":"..."}
```

The previous segment's head hash is in **`prev_hash`** — the field every
record already uses for exactly that. ROADMAP B3's phrasing ("an anchor record
carrying the previous segment's head hash") anticipated a new field; none is
needed, because the anchor is simply the chain's next record and rotation
writes it as such. What the anchor adds that `prev_hash` cannot is the
previous segment's **name**, and that is what makes a segment
self-describing.

### The swap

Under the `flock` on the active segment, in this order:

1. Write the anchor into a staging file `<path>.rotating`; flush; fsync it if
   `durability == "fsync"`.
2. `os.link(path, closed_name)` — the closing segment now has *two* names, one
   of which is still `[audit].path`.
3. **fsync the parent directory.** The `replace` below depends on both of the
   names created above; see decision 17.
4. `os.replace(staging, path)` — atomically, `[audit].path` stops meaning the
   old inode and starts meaning the new one, which **already contains the
   anchor**.
5. fsync the parent directory again.

There is no instant at which `[audit].path` does not exist, and no instant at
which it names an empty file. That is the invariant, held by `link` before
`replace` rather than by luck.

### How this meets B2

Two questions the handover raised, both answered rather than assumed.

`append()`'s `if seq == 0` directory fsync — B2's guard for "fsync makes the
file's contents durable and says nothing about the directory entry that makes
it findable" — does **not** fire once per segment, because a new segment is
never empty when an append reaches it: rotation puts the anchor in it before
it has the active name, so the tail read returns the anchor's seq, never 0.
The property B2 wanted is met by `_rotate`'s own directory fsync instead, at
exactly the moment the new directory entry appears. The `seq == 0` branch stays
what it was: once in a log's life.

And the record's *own* durability survives rotation for the same reason it
needs step 5 above. The record is written into the new active segment after the
`replace`, and its bytes are fsynced by the existing per-append fsync — but its
**name** is the `replace`, so a `replace` that is not durable leaves the record
in a nameless inode after a power loss. That is B2's failure exactly, one level
up, and step 5 is the same fix.

### The staleness check

Every append, after taking the `flock` and before anything else: compare the
`(st_dev, st_ino)` of the held descriptor with the `(st_dev, st_ino)` of
`[audit].path`. If they differ, this writer is holding a segment that was
closed underneath it — close it (releasing the lock) and start over. Bounded by
the same deadline the `flock` spin uses.

### The guards

Four, each of which the spike produced and none of which is hypothetical:

| state | what happens |
|---|---|
| the closed name exists and is a *different* file | `OSError: audit segment audit-000008.jsonl already exists and is not this log` |
| the closed name exists and is the *same* inode (crash between link and replace) | rotation completes it; reads during the window are correct and verify intact |
| a segment's anchor names a predecessor that is not there | `OSError: audit segment audit-000008.jsonl is missing (named by audit-000016.jsonl)` |
| the active segment is empty and foreign closed segments exist | `OSError: audit log is empty but segment files exist: refusing to start a second chain at genesis` |

All of it measured:

```
  a) crash after link, before replace: files ['audit-000008.jsonl', 'audit.jsonl']
     read DURING the window: 8 records, verify=(True, None)
     next append -> seq 10; then 10 records, verify=(True, None), files ['audit-000008.jsonl', 'audit.jsonl']
  b) closed name taken by a FOREIGN file: OSError(audit segment audit-000008.jsonl already exists and is not this log)
  c) oldest segment pruned: OSError(audit segment audit-000008.jsonl is missing (named by audit-000016.jsonl))
  d) anchor naming an absolute path: OSError(audit segment anchor names an illegal previous: '/etc/passwd')
  e) active file deleted: OSError(audit log is empty but segment files exist: refusing to start a second chain at genesis (['audit-000008.jsonl', 'audit-000016.jsonl', 'audit-000024.jsonl']))
  f) fsync rotation: 28 records dense=True verify=(True, None) segments=4
  g) shipped-written log read by the prototype: 5 records, verify=(True, None), segments=['audit.jsonl']
     after the prototype rotates it: verify=(True, None), 28 records; the SHIPPED reader sees 4 (the active segment only)
  h) an [audit].path with no suffix: 28 records, verify=(True, None), files ['auditlog', 'auditlog-000008', 'auditlog-000016', 'auditlog-000024']...
```

Row (g) is the compatibility answer in both directions. A log written before
B3 is a valid segment 0 and needs no migration. And an **old** warden pointed
at a **rotated** log does not quietly under-report — measured against the
shipped CLI:

```
shipped `warden verify-chain` on a rotated log -> exit 1 | chain BROKEN at seq 25
```

The active segment starts with an anchor whose `prev_hash` is not genesis, so
the pre-B3 verifier says BROKEN and exits 1. A downgrade fails loudly, in the
safe direction, rather than reporting "chain intact: 4 records" over a log
with 28.

## Decisions, each with the alternative it beat

**1. Rotation happens inside `append()`, triggered by size.**
Beat an explicit `warden rotate` and an age trigger. The size is already in
hand (the tail read fstats the file), so the check is free — measured
indistinguishable. An explicit command does not reduce the concurrency risk it
appears to: an operator running `warden rotate` while the broker appends *is*
the two-writer case, so it needs every mechanism below and adds a second code
path that must get it right. It also leaves the log unbounded whenever nobody
runs it, which is the failure the feature exists to prevent. An age trigger
needs a duration in the config and a "when did this segment start" read, for a
need nobody has stated.

**2. The active segment keeps `[audit].path`; closed segments are siblings.**
Beat making `[audit].path` a directory. `[audit].path` names a file in both
shipped TOMLs, in `warden verify-chain --audit`, in the frozen golden chain,
in every test and in `docs/WALKTHROUGH.md`. Redefining it would migrate all of
that to buy a tidier layout. Beat also numbering the active segment
(`audit-000001.jsonl` as the newest): then "which file do I append to" becomes
a directory scan, and the scan is racy in exactly the way § 4 below is about.

**3. The swap is staging → `link` → `replace`.**
Beat rename-then-recreate, which is Q1: the log restarts at genesis and every
record still verifies. Beat `copytruncate` (copy the content out, truncate the
active file in place), which needs no staleness check at all because the inode
never changes — and loses on two counts. It is O(size) under the lock, so a
64 MiB segment holds every writer for the duration of a 64 MiB copy; and it
pulls the content out from under any *reader*, so a `warden verify-chain`
running concurrently sees a file that shrinks mid-read. `link`-then-`replace`
leaves concurrent readers holding a complete, immutable inode.

**4. A staleness check on every append, unconditionally.**
Beat a dedicated `<path>.lock` file, whose inode never moves and which
therefore needs no staleness check at all. Two reasons. A zero-byte file named
`audit.jsonl.lock` in a data directory looks exactly like leftover garbage, and
an operator who deletes it silently removes multi-writer exclusion with nothing
anywhere complaining — a hazard with no equivalent for the log file itself.
And B6's decision was that the lock's scope should be exactly the resource and
that the kernel should release it when the holder dies; the active segment
still satisfies both, provided a writer notices when the segment it holds stops
being the active one. That noticing is the check. Beat also gating the check on
`segment_bytes != 0`: it would save 6.7 µs at `flush` and nothing at the
default, in exchange for a correctness check whose presence depends on a config
value.

**5. The retry is bounded by the lock timeout deadline, not by an attempt
count — and the deadline covers the whole `append()`, not each attempt.** A
first draft allowed four attempts. Measured, at a 4 KiB segment, that killed
one of four writers with *"audit log was rotated out from under this writer
repeatedly"* — legitimately, because rotation was happening every eight records
across four processes. The deadline reuses the constant that already bounds the
`flock` spin, produces the same `OSError` the spine already turns into a
recorded refusal, and took the failure to 0 of 4 across three runs.

Each retry passes `_acquire` the *remaining* budget rather than the full
`lock_timeout`. Giving each attempt its own five seconds would let one
`append()` block for a multiple of the constant whose entire documented purpose
is that "one wedged writer wedges every worker" cannot happen — a two-attempt
append could hold a pool thread for ten seconds against a limit that says five.

**6. At most one rotation per `append()` call.** A local flag, not a
condition on the file. Without it, a pathologically small `segment_bytes` (say
100, below one record) makes every append rotate, reopen, find the new segment
also over the threshold, rotate again — until the deadline, so appends *fail*
rather than merely producing tiny segments. With it, progress is guaranteed for
any threshold: a segment holds at most `max(segment_bytes, anchor + one
record)`. Beat enforcing a minimum `segment_bytes` large enough to make the
pathology unreachable, which would force every rotation test to write megabytes
and make the suite pay for a config nobody sane writes.

**7. The anchor is an ordinary record — the same thirteen body fields, with
`action.type = "anchor"` and the previous segment's name in `target`.**
Beat a fourteenth body field, on B7's decision 9 precedent: a `mint` record
reused the thirteen fields precisely so the record shape stays one shape and
`AuditLog` needs no new field. `target` already means "the thing this action is
about" — a document, a query, a host, a recipient, for a mint the authority
granted, and here the segment that closed. Beat also **no anchor at all**,
which is a stronger option than it looks: concatenating segments in order
already verifies end to end, because `prev_hash` links across the boundary
untouched. What the anchor buys is retention. An operator who archives
`audit-000008.jsonl` to cold storage leaves a log whose oldest record links to
a hash nobody can produce — indistinguishable from tampering. With an anchor,
the remaining files still say *which* file is absent and what its head hash
was. That is the same "a `prev_hash` nobody can supply" failure B6 rejected the
Redis-CAS design for, met on the reading side.

**8. The previous head hash lives in `prev_hash` and nowhere else.** Beat
duplicating it into `target` alongside the name. The anchor is written as the
closing segment's successor, so the two values cannot differ; a field that can
never disagree with another field is not a check, it is a second thing to keep
in sync.

**9. Segments are discovered by walking the anchors backward from the active
file.** Beat globbing `<stem>-*<suffix>` and sorting. The walk is explicit
content, so it cannot be fooled by a filename, it needs no pattern to be
authoritative, and a missing segment is diagnosable *as* a missing segment
rather than as a hash mismatch at an arbitrary seq. It costs one `readline`
per segment — 27 µs, measured.

**10. `target.previous` is a bare filename, and a value containing a path
separator is refused.** Relocatable: copy or mount the log's directory
anywhere and the walk still works, which an absolute path would not survive.
And a log is precisely the artifact that may have been hand-edited, so a
crafted anchor naming `/etc/passwd` or `../../secrets` must not become a file
this code opens. Measured: refused.

**11. A closed-segment-shaped file whose inode is already in the walk is not
an orphan.** Identity by `(st_dev, st_ino)`, not by name. The first draft
compared resolved paths, and the crash window between `link` and `replace`
leaves two *names* for one inode — so a log that was completely fine reported
`audit log has segment files nothing in the chain names: ['audit-000010.jsonl']`
and could not be read at all until the next rotation, ~64 MiB of writes later.
With inode identity, reads during that window return 8 records and verify
intact, and the next append completes the rotation.

**12. An active segment whose head reads as genesis, with foreign closed
segments present, refuses the append.** Beat starting a second chain at
genesis, which is Q1's silent fork arriving by another route — an operator
deleting `audit.jsonl` while segments exist. Gated on the **head**, not on
`st_size == 0`: `_head_from_tail` also answers `(0, GENESIS_HASH)` for a file of
nothing but newlines, so a size test leaves a hole exactly where the existing
code already has a documented special case. It runs only when the head is
genesis — once in a log's life — so it costs nothing in steady state. It does
**not** catch an external `logrotate` that moves the file aside under its own
naming; see *what this does not do*.

**13. An absent predecessor refuses the read.** Beat verifying whatever suffix
of the log is present, which reports `chain BROKEN at seq N` — calling a
deliberate operator action tampering. Beat also returning the partial log
silently, which is worse: `warden replay` would render a task's records and
print *chain intact* over a log missing its beginning. The refusal names both
the missing file and the file that named it. Pruning an audit log is a real
operator need and B3 does not serve it; it makes it *possible* (whole files,
where before there was one file) and leaves the verdict to B4.

**14. `[audit].segment_bytes` in both TOMLs, default 64 MiB, `0` disables, and
the two values need not agree.** Default **on**, beating default-off: a
deployment that reaches 64 MiB has ~123,000 records and a real operational
problem, and one that never reaches it (the demo writes 8 records) is
unaffected — so default-off would ship a feature only the operators who
already read the ROADMAP would get. 64 MiB beats 16 MiB (33 segments per
million records) and 256 MiB (2 per million): the ROADMAP's exit is a
*million-record log that verifies across rotation*, and 8 segments is the
granularity that actually exercises it. `0` rather than a separate flag,
because the loader's `_positive(..., allow_zero=True)` already means exactly
this. In both TOMLs on B2's `durability` precedent — the control plane writes
into the same chain and would otherwise rotate at a threshold nobody wrote —
and, like `durability` and unlike `path` and `issuer`, **not** compared: a
disagreement makes segment sizes irregular, which is untidy and not a
misconfiguration.

**15. `_describe` in `warden/cli/replay.py` gets an anchor branch; the
`✓`/`✗` mark logic is not touched.** The renderer has three precedents for
this exact thing (`tool_list`, `mcp_handshake`, `mint`), and without a fourth
an anchor renders `?()`. The mark is a different question: `replay.py` renders
anything that is not `decision == "allow"` as `✗ DENY`, so an anchor that ever
reached the renderer would look like a refusal. It cannot today — `task_id` is
`"-"`, and `warden replay` filters by `task_id` — and what the CLI should say
about segments is B4's subject. Fixing the mark here would be redesigning the
replay line on the way past.

**16. Rotation's fsyncs follow `[audit].durability`.** At `"flush"` neither
the staging file nor the directory is fsynced. The level's promise is "survives
this process, not the host", and spending 3.1 ms per rotation to half-honour a
promise the operator declined is the kind of inconsistency that makes a
config key mean two things.

**17. Rotation fsyncs the directory twice: once between the `link` and the
`replace`, once after.** The second one is durability (see *how this meets B2*).
The first one is **ordering**, and it is the one that is easy to leave out. Both
steps are directory metadata in the same directory, unfsynced, so nothing in
POSIX orders them: a filesystem free to make the `replace` durable while the
`link` is not would leave `[audit].path` naming the new segment and the closing
segment with **no name at all** — the anchor pointing at a file that does not
exist, and the records unrecoverable. Journalling filesystems happen not to do
this; the cost of not depending on that is 1.4 ms once per ~123,000 records.
Beat relying on ext4's ordering, which is a property of one filesystem and not
of the interface this code is written against.

**18. Closed-segment-shaped siblings are found with `iterdir()` and a compiled
regex, never with `glob()`.** `Path.glob(f"{stem}-*{suffix}")` interprets the
*stem* as a pattern, so an `[audit].path` containing `[`, `*` or `?` would make
the glob search for a different set of names than the regex accepts — and the
direction of that mismatch is the dangerous one: the orphan guard would find
nothing and silently pass. `iterdir()` lists the directory exactly once, which
`glob` does anyway, so this costs nothing.

**19. `segments()` is public.** Same reason `durability` is: B4 is about
teaching the CLI what a segmented log is, and a test that asserts which files a
log is made of should read the answer rather than mock its way to one.

## What this does not do

* **It does not let a log be pruned.** An anchor naming an absent predecessor
  is an `OSError`, by decision 13. Rotation makes whole-file archival
  *possible*; making a pruned log verifiable from seq N with its predecessor
  declared absent is B4's, and until then archiving the oldest segment makes
  `warden verify-chain` refuse rather than lie.
* **It does not detect an external rotator.** `logrotate` moving
  `audit.jsonl` to `audit.jsonl.1` leaves no closed-segment-shaped sibling, so
  the empty-active guard does not fire and warden starts a fresh chain at
  genesis — exactly Q1. Warden's audit log must not be given to an external
  rotator; `[audit].segment_bytes` is how you rotate it.
* **It does not bound the number of segments, and cannot.** At the ~590
  records/second audit ceiling B2 measured, a 64 MiB segment lasts ~3.5
  minutes; at a more realistic 10 records/second, ~3.4 hours. Retention is
  B5's.
* **It does not clean up after a crash.** A crash between `link` and `replace`
  leaves an extra *name* for a segment, and a crash while staging leaves a
  `<path>.rotating` file. Both are harmless — the extra name is skipped by
  inode identity, the staging file is overwritten by the next rotation — and
  neither is deleted, because this file does not delete bytes in the audit
  directory. It also does not remove them from an operator's `ls`.
* **It does not make `verify-chain`'s record count honest about anchors.**
  `records()` includes them, so `chain intact: 182 records` counts 22 anchors
  among 160 decisions. B4.
* **It does not tell a reader which durability a segment was written at.**
  Same gap B2 recorded, unchanged.
* **It does not work on a filesystem without hard links.** `os.link` is the
  step that keeps `[audit].path` continuously non-empty; on a filesystem that
  refuses it the `OSError` propagates into the spine's existing handling and the
  append becomes a recorded refusal. There is no fallback, deliberately: the
  only fallback available is rename-then-recreate, which is Q1.
* **It does not decide what `warden verify-chain` should say.** A segment
  problem is an `OSError`, so it lands in `replay.py`'s existing "cannot read
  audit log" branch and exits **2**, where a tampered record exits 1 with
  `chain BROKEN`. A hand-edited anchor is therefore reported as unreadable
  rather than as broken. Nothing tracebacks and the message names the real
  problem, which is what B3 owes; mapping segment failures onto the right
  verdict and exit code is precisely what B4 is.

## Proof table

Each row is a property, the test that holds it, and the mutation that must
make that test — named, so that a mutation reddening a *different* test is
visible as a miss.

| | property | test | mutation that must redden it |
|---|---|---|---|
| 1 | Crossing the threshold closes a segment, named for its last seq | `test_crossing_the_threshold_closes_a_segment` | never rotate (`if False`) |
| 2 | The active segment's first record is the anchor, written before the name changes | `test_the_new_segment_holds_its_anchor_before_it_is_the_active_segment` | `rename` then let `"a+b"` recreate (Q1's order) |
| 3 | A rotated log verifies end to end with dense seqs | `test_a_rotated_log_verifies_end_to_end` | anchor `prev_hash = GENESIS_HASH` |
| 4 | The anchor names the segment that closed | `test_the_anchor_names_the_previous_segment` | `previous` = `""` |
| 5 | The anchor carries exactly a decision record's fields | `test_an_anchor_has_exactly_a_decision_records_fields` | add a 14th field to the anchor body |
| 6 | Four processes across rotations produce one intact chain | `test_two_processes_rotating_produce_one_intact_chain` | drop the staleness check |
| 7 | A writer whose segment was rotated away reopens instead of writing into it | `test_a_writer_whose_segment_was_rotated_away_reopens` | drop the staleness check |
| 8 | Being rotated out forever is a bounded `OSError` | `test_endless_rotation_gives_up_as_an_oserror` | loop without the deadline |
| 9 | One rotation per append, so any threshold makes progress | `test_a_threshold_below_one_record_still_makes_progress` | drop the `rotated` flag |
| 10 | `fsync` rotation syncs the staging file and the directory; `flush` syncs neither | `test_rotation_fsyncs_the_new_segment_and_the_directory`, `test_flush_durability_does_not_fsync_a_rotation` | drop the `durability` condition in `_rotate` |
| 11 | The crash window reads as an intact log and the next append completes it | `test_a_crash_between_link_and_replace_is_readable_and_completes` | orphan identity by name instead of inode |
| 12 | A foreign file at the closed name refuses the rotation | `test_a_foreign_file_at_the_closed_name_refuses_the_rotation` | drop the inode comparison in the `FileExistsError` branch |
| 13 | An emptied active segment beside real segments refuses the append | `test_an_emptied_active_segment_beside_segments_refuses_the_append` | drop the guard |
| 14 | An absent predecessor refuses the read, naming both files | `test_an_absent_predecessor_refuses_the_read` | `break` instead of `raise` |
| 15 | An anchor naming a path, not a filename, refuses the read | `test_an_anchor_naming_a_path_refuses_the_read` | drop the separator check |
| 16 | Segment files nothing names refuse the read | `test_orphaned_segments_refuse_the_read` | drop the orphan check |
| 17 | An anchor cycle refuses the read | `test_an_anchor_cycle_refuses_the_read` | drop the `seen` set |
| 18 | A pre-B3 single-file log reads, verifies, and rotates | `test_a_log_written_before_segments_still_reads_and_rotates` | require an anchor in every segment |
| 19 | An `[audit].path` with no suffix rotates and reads | `test_a_path_with_no_suffix_rotates` | build the closed name by stem/suffix slicing |
| 20 | The configured `segment_bytes` reaches both logs | `test_the_broker_builds_its_audit_log_with_the_configured_segment_bytes`, `..._the_control_plane_...` | ignore the config value in `build()` |
| 21 | `segment_bytes` parses in both loaders, defaults to 64 MiB, and the two may differ | `test_audit_segment_bytes_defaults_to_64_mib`, `test_the_two_writers_may_choose_different_segment_bytes` | default to `0` |
| 22 | A negative `segment_bytes` is refused by the constructor and the loader | `test_a_negative_segment_bytes_is_refused_by_the_constructor`, `test_a_negative_segment_bytes_is_a_config_error` | drop the validation |
| 23 | `warden replay` renders an anchor rather than `?()` | `test_replay_describes_an_anchor_record` | delete the `_describe` branch |
| 24 | A newline-only active segment is caught by the same guard as an emptied one | `test_a_newline_only_active_segment_refuses_the_append` | gate the guard on `st_size == 0` |
| 25 | An `[audit].path` whose name contains glob metacharacters is still guarded | `test_a_path_with_glob_metacharacters_still_finds_its_segments` | find siblings with `glob()` instead of `iterdir()` |
| 26 | A rotating append fsyncs the directory before the `replace` and after it | `test_rotation_fsyncs_the_directory_before_and_after_the_replace` | drop the pre-`replace` directory fsync |
| 27 | The whole append is bounded by one `lock_timeout`, not one per attempt | `test_each_retry_gets_what_is_left_of_the_one_lock_timeout` | pass `self._lock_timeout` to each `_acquire` |

## Files

| file | change |
|---|---|
| `warden/broker/audit.py` | `segment_bytes` on the constructor; the retry loop, staleness check and guards in `append`; `_rotate`, `segments`, `_closed_shaped`, `_identity`; `records` reads every segment |
| `warden/broker/config/loader.py` | `audit_segment_bytes` on both configs, parsed by the existing `_positive(..., allow_zero=True)` |
| `warden/broker/__main__.py`, `warden/broker/control_main.py` | pass it to the `AuditLog` they build |
| `warden/broker/record_fields.py` | `empty_task_state`'s docstring gains its third caller |
| `warden/cli/replay.py` | `_describe`'s fourth branch |
| `demo/scenario/warden.toml`, `demo/scenario/control.toml` | the key, with the note |
| `docs/ROADMAP.md` | strike B3, record what was measured, update § B's exit |
| `docs/ARCHITECTURE.md` | the audit row names a segmented log |
| `tests/warden/test_audit.py`, `test_config_loader.py`, `test_key_split.py`, `tests/demo/test_cli.py` | the proof table |

## What the review changed

Eight finds, all before any implementation existed. Four changed the mechanism
and are folded into the decisions above; four changed what the spec claims.
The two worth carrying forward are 4 and 8 — both are cases where the first
draft was *correct on the filesystem it was tested on* and wrong about the
interface it is written against.

**1 — the orphan glob interprets its own stem.** `Path.glob(f"{stem}-*")`
with a stem containing `[`, `*` or `?` searches a different set of names than
the regex accepts, and the mismatch silently *empties* the guard rather than
tripping it. Now `iterdir()` plus a compiled `re.escape`d pattern. Decision 18.

**2 — the emptied-active guard was gated on `st_size == 0`.** `_head_from_tail`
already documents a second way to read as genesis: a file of nothing but
newlines. So the guard had a hole in exactly the place the code it guards
already has a special case. Now gated on the head being `(0, GENESIS_HASH)`.
Decision 12.

**3 — the closed-name collision check was the only thing standing between a
stale writer and a forked segment tree.** Reading the spike output again: the
three dead workers in the no-check runs died on *that* guard, not on the
staleness check. It was written as crash recovery and was silently doing
double duty. Both are kept and the spec now says which failure each one is for;
they are layered, not redundant.

**4 — each retry was given a fresh `lock_timeout`.** So an `append()` that
retried twice could hold a threadpool thread for 10 s against a constant whose
own comment says the bound exists so that one wedged writer cannot wedge every
worker. Now the deadline covers the whole call and `_acquire` gets what is left
of it. Decision 5.

**5 — `records()` reading every segment collides with an existing test.**
`test_appending_does_not_re_read_the_log` shadows `log.records` and asserts
`append` never calls it. Checked: rotation reads the tail and the directory,
never `records()` or `segments()`, so the B1/B6 property survives. Recorded
here because the next person to add a read to the append path will not know
that test exists.

**6 — a segment failure exits 2, not 1.** `replay.py` maps `OSError` to
"cannot read audit log" and exit 2; a tampered anchor is therefore reported as
unreadable rather than as `chain BROKEN`. Not fixed here: introducing an
exception subclass so the CLI can tell the two apart is what B4 is for. Now
stated as a *does not do* rather than left to be discovered.

**7 — `segments()` was private.** It is the one question B4 and every rotation
test need to ask. Public, on the `durability` precedent. Decision 19.

**8 — nothing ordered the `link` before the `replace`.** Both are unfsynced
directory metadata; POSIX orders neither. A filesystem that made the `replace`
durable first would leave the closing segment with no name and its records
unrecoverable — the worst outcome in this whole design, reachable only through a
window nobody would test. The first draft was relying on ext4's journalling
without saying so. Now a directory fsync sits between them. Decision 17.

Two things the review explicitly declined to change. The anchor's `decision` is
`"none"`, which `replay.py` would render as `✗ DENY` if it ever reached the
renderer — it cannot, and fixing the mark is B4's (decision 15). And no
`warden config check` advisory for an absurdly small `segment_bytes`: that
module is about the tool catalog against the policy data document, and putting
an unrelated check there because it is the file that already prints advisories
is how a module stops having a subject.

## What the mutation pass found

31 mutations across the 27 proof-table rows (four rows need two mutations, one
in each direction). **29 reddened the test their row names.** Two could not, for
a reason worth keeping. One row was a list of intentions and is now a test.

**Row 27 reddened nothing.** `test_endless_rotation_gives_up_within_one_lock_timeout`
pins that a writer rotated out forever gives up, and gives up as an `OSError` --
and does not pin the budget arithmetic at all. Passing `self._lock_timeout` to
every attempt instead of `max(0.0, deadline - now)` changed nothing that test
could observe, because nothing in it contends for the lock, so `_acquire` returns
immediately whatever timeout it is handed. The property is real — a two-attempt
append could hold a pool thread for twice the constant whose own comment is about
not wedging every worker — so it now has
`test_each_retry_gets_what_is_left_of_the_one_lock_timeout`, which reads the
budget `_acquire` is actually given and forces exactly one retry through the
staleness check rather than through a real rotation. That mutation now reddens it.

**Two mutations HUNG rather than failing, and that is the proof.** Removing the
anchor-cycle check (row 17) and removing the give-up branch entirely (row 8b) each
delete a *liveness* property, so the test they guard cannot report FAILED — it can
only never finish. The harness times out at 240 s and records `HUNG` as its own
verdict, distinct from both `RED` and `NOT REDDENED`, because a run that simply
never returned would otherwise be filed as either. Row 8's other half is mutated
into a `RuntimeError` instead, which does redden: the type is what the spine's
`except OSError` depends on.

**The harness caught a collision in its own mutation.** `if time.monotonic() >=
deadline:` appears twice — once in `append`'s retry epilogue and once inside
`_acquire`'s own flock spin — so the row-8b mutation would have silently patched
the wrong one as well. The uniqueness assertion reported *2 of an expected 1* and
the mutation was rewritten with two lines of context. This is the second time in
this project that a mutation string mattering more than the mutation has cost
something; the harness asserting an expected count (rather than merely
uniqueness) is what makes a deliberately-two-site mutation — row 22b, which must
hit both loaders — distinguishable from an accidental one.

**One row has no mutation that reddens it alone, and the row was wrong about
why.** Row 19 (an `[audit].path` with no suffix) was written expecting to be
broken by "build the closed name by stem/suffix slicing" — a shape the
implementation does not have, because `Path.stem` and `Path.suffix` do the split
and handle an empty suffix themselves. What actually reddens that test is the
never-rotate mutation, which also reddens row 1. The test is kept: it is cheap,
and it exercises a real `[audit].path` shape end to end. But it is documentation
of a rejected design rather than a guard on a branch this code owns, and saying
so is better than leaving a row that looks proven by a mutation of its own.

Everything else went red on the first attempt, which is the quietest possible
outcome and the one worth being slightly suspicious of. The reason it happened
here and not in B2 is that the 27 rows were written from a spike that had already
*produced* every failure they describe — the fork at genesis, the dead writers,
the unreadable log, the crash window — so the tests were written against observed
behaviour rather than imagined behaviour.
