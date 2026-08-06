"""The shared task-state store: the same contract, in Redis.

Designed in docs/superpowers/specs/2026-08-06-p2a2-the-shared-store-design.md,
against a live server rather than against an argument -- two of that
document's five decisions were found by a spike failing.

One key per task, one script per operation, and every script is one atomic
step. The layout is a single hash so that the whole of a task's state shares
one key, one expiry and one cluster slot:

    c            committed rows, an integer
    x            expires_at, epoch SECONDS
    k:<class>    a class some settled call committed
    r:<id>       a reservation, "<rows>:<deadline>:<class>"

The class lives on the RESERVATION, not in `k:` -- releasing a charge has to
drop the class it claimed without touching one a settled call committed, and
holding a single per-task set makes that undecidable for a zero-row read.
warden/broker/taint.py's _Reservation docstring records that this was tried
and abandoned.
"""

from __future__ import annotations

from typing import Any

from warden.broker.taint import TaskStateUnavailable

__all__ = ["RedisTaskStateStore", "TaskStateUnavailable", "connect"]

# Kept out of the scripts and applied in Python, deliberately:
#
#   * sorted() -- Lua's table.sort on strings compares with strcoll, which is
#     locale-dependent. Python's sort is not.
#   * the return shape -- a flat array, never cjson. Redis's bundled cjson
#     encodes an EMPTY table as a JSON object ({}), while fakeredis encodes it
#     as an array ([]), so a contract suite that ran on fakeredis would be
#     green while production denied every call with input.malformed on
#     authz.rego's is_array guard.
#   * int() -- authz.rego denies input.malformed unless rows_charged_so_far
#     is_number, and RESP bulk strings arrive as bytes.

_PRELUDE = """
local key = KEYS[1]
local now = tonumber(ARGV[1])

-- Eviction is a RESET, not a carry-forward: an expired task's committed rows
-- and classes must not be resurrected by the next call that touches it. This
-- runs before anything reads the hash, and mirrors _live() in taint.py.
local x = redis.call('HGET', key, 'x')
if x and tonumber(x) and tonumber(x) <= now then
  redis.call('DEL', key)
end
"""

# Sums committed + live reservations and collects the classes, pruning any
# reservation whose deadline has passed. Leaves `total` and `classes` set.
_VIEW = """
local committed = tonumber(redis.call('HGET', key, 'c') or '0')
local total = committed
local classes = {}
local seen = {}
local fields = redis.call('HGETALL', key)
for i = 1, #fields, 2 do
  local f = fields[i]
  local v = fields[i + 1]
  if string.sub(f, 1, 2) == 'r:' then
    local rrows, rdeadline, rclass = string.match(v, '^(-?%d+):(-?%d+):(.*)$')
    if rrows == nil then
      return redis.error_reply('corrupt reservation: ' .. f)
    end
    if tonumber(rdeadline) <= now then
      if PRUNE then redis.call('HDEL', key, f) end
    else
      total = total + tonumber(rrows)
      if rclass ~= '' and not seen[rclass] then
        seen[rclass] = true
        classes[#classes + 1] = rclass
      end
    end
  elseif string.sub(f, 1, 2) == 'k:' then
    local kclass = string.sub(f, 3)
    if not seen[kclass] then
      seen[kclass] = true
      classes[#classes + 1] = kclass
    end
  end
end
"""


def _view(prune: bool) -> str:
    return _VIEW.replace("PRUNE", "true" if prune else "false")


# charge: reserve this call's price, return the state as it was BEFORE it.
#
# The ORDER is the whole of "a call cannot deny itself": the view is computed,
# and only then is this caller's own reservation written. Other callers'
# in-flight rows are in the answer; this one's are not.
_CHARGE = (
    _PRELUDE
    + """
local cid = ARGV[2]
local rows = tonumber(ARGV[3])
local class = ARGV[4]
local expires_at = tonumber(ARGV[5])
local max_in_flight = tonumber(ARGV[6])

-- Validated before ANY write below. Redis does not roll back a partially
-- executed script, so a script that mutates and then errors leaves the
-- mutation behind -- and the spine reports that as "nothing happened".
if redis.call('HEXISTS', key, 'r:' .. cid) == 1 then
  return redis.error_reply('charge_id already in flight')
end
"""
    + _view(prune=True)
    + """
-- max(rows, 0). A negative estimate is denied by R1b as input.malformed, but
-- that decision happens AFTER this charge; reserving a negative would hand
-- budget back to a concurrent caller in the window before the denial
-- releases it.
if rows < 0 then rows = 0 end

redis.call('HSET', key, 'r:' .. cid,
           rows .. ':' .. (now + max_in_flight) .. ':' .. class)

-- Never shortens: task state deliberately outlives one token, so a
-- short-lived renewal must not truncate what a longer one set.
local cur = tonumber(redis.call('HGET', key, 'x') or '0')
if expires_at > cur then
  redis.call('HSET', key, 'x', expires_at)
  cur = expires_at
end
-- A RELATIVE ttl, derived from the caller's clock -- not EXPIREAT, and
-- emphatically not PEXPIREAT.
--
-- The key's own expiry runs on Redis's WALL clock; `x` is on whatever clock
-- the caller injected. Those are the same clock in production (the spine
-- passes int(time.time())) and are not the same clock under test, where the
-- suite drives now=1000 against expires_at=10^9 -- "far future" on the fake
-- timeline, September 2001 in real time. EXPIREAT would delete the key on
-- every charge; measured, not reasoned.
--
-- Subtracting turns the absolute logical instant into a duration, which is
-- correct on both clocks. And this TTL is only ever a garbage collector: the
-- `x` field checked against the caller's `now` is what decides whether a
-- task is live, exactly as _live() rather than _sweep() decides it in
-- taint.py.
redis.call('EXPIRE', key, cur - now)

local out = {total}
for i = 1, #classes do out[#out + 1] = classes[i] end
return out
"""
)

_PEEK = (
    """
local key = KEYS[1]
local now = tonumber(ARGV[1])
"""
    # No PRELUDE: peek must not create OR delete. An expired task is simply
    # not reported, which is behaviourally identical to deleting it -- every
    # mutating path re-checks expiry itself -- and it keeps this operation
    # read-only, so it can run on a replica and cannot leak a key per
    # arbitrary task_id an operator or a CONNECT probe asks about.
    + _view(prune=False)
    + """
if redis.call('EXISTS', key) == 0 then return {0} end
local x = redis.call('HGET', key, 'x')
if x and tonumber(x) and tonumber(x) <= now then return {0} end
local out = {total}
for i = 1, #classes do out[#out + 1] = classes[i] end
return out
"""
)

# The three endings. Each takes the reservation off the hash; they differ only
# in what they keep.
#
# A MISSING reservation is not an error in any of them: the deadline may have
# collected it first, and a settle that raced its own expiry must not fail
# after the action has already happened.
#
# Every one of them guards on the key still existing. HSET and HINCRBY
# auto-create, so an unguarded settle against an evicted task would resurrect
# it -- with no `x` field, therefore no TTL, therefore an immortal key.
_SETTLE_TEMPLATE = (
    _PRELUDE
    + """
local cid = ARGV[2]
local commit_rows = tonumber(ARGV[3])
local explicit_class = ARGV[4]

if redis.call('EXISTS', key) == 0 then return 0 end

local held = redis.call('HGET', key, 'r:' .. cid)
redis.call('HDEL', key, 'r:' .. cid)

if KEEP_CLASS then
  if held then
    local _, _, rclass = string.match(held, '^(-?%d+):(-?%d+):(.*)$')
    if rclass and rclass ~= '' then
      redis.call('HSET', key, 'k:' .. rclass, '1')
    end
  end
  if explicit_class ~= '' then
    redis.call('HSET', key, 'k:' .. explicit_class, '1')
  end
end

if commit_rows > 0 then
  redis.call('HINCRBY', key, 'c', commit_rows)
end

-- Refresh the garbage-collection TTL from `x`, so a long task that settles
-- more often than it charges cannot have its key collected while its own
-- clock still considers it live. Same reasoning as charge's EXPIRE.
local cur = tonumber(redis.call('HGET', key, 'x') or '0')
if cur > now then
  redis.call('EXPIRE', key, cur - now)
end
return 1
"""
)


def _settle_script(keep_class: bool) -> str:
    return _SETTLE_TEMPLATE.replace("KEEP_CLASS", "true" if keep_class else "false")


def connect(url: str, *, socket_timeout_seconds: int):
    """A client with retries OFF and a bounded timeout.

    Both defaults in redis-py are wrong for this store, and both were
    measured (6.4.0: `Retry(retries=3)` over ConnectionError/TimeoutError,
    `socket_timeout=None`).

    Retries are off because `charge` is deliberately anti-idempotent -- a
    duplicate charge_id is an error -- so retrying after a LOST REPLY, which
    is exactly the case where the script already ran, turns a transient blip
    into a guaranteed refusal. `reconcile` is worse: HINCRBY is not idempotent
    at all, so three retries commit the rows three times and the budget is
    wrong, fail-closed but arithmetically false, for the task's whole life.

    Doing nothing instead is already paid for: a lost charge leaves a
    reservation that its own deadline collects within max_in_flight_seconds,
    which is the mechanism decision 4 of the P2-A spec bought.

    The timeout is bounded because a hung server would otherwise block the
    calling thread forever, and since A6 those threads are a pool of 16
    shared with the egress proxy -- an unreachable-but-not-refusing Redis
    would exhaust the broker rather than fail it.
    """
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    return redis.Redis.from_url(
        url,
        socket_timeout=socket_timeout_seconds,
        socket_connect_timeout=socket_timeout_seconds,
        retry=Retry(NoBackoff(), 0),
        retry_on_error=[],
    )


class RedisTaskStateStore:
    """The same five methods, over one Redis key per task."""

    def __init__(self, client: Any, *, max_in_flight_seconds: int = 60,
                 prefix: str = "warden:task:") -> None:
        self._redis = client
        self._max_in_flight = max_in_flight_seconds
        self._prefix = prefix
        self._charge = client.register_script(_CHARGE)
        self._peek = client.register_script(_PEEK)
        self._reconcile = client.register_script(_settle_script(keep_class=True))
        self._release = client.register_script(_settle_script(keep_class=False))
        self._abandon = client.register_script(_settle_script(keep_class=True))

    def _key(self, task_id: str) -> str:
        return f"{self._prefix}{task_id}"

    @staticmethod
    def _decode(reply: list) -> dict:
        """A flat array into the one dict both the policy input and the audit
        record carry. int() and sorted() happen HERE -- see the module note."""
        classes = [
            value.decode("utf-8") if isinstance(value, bytes) else str(value)
            for value in reply[1:]
        ]
        return {
            "data_classes_held": sorted(classes),
            "rows_charged_so_far": int(reply[0]),
        }

    @staticmethod
    def _run(script, *, keys: list, args: list, charge_id: str = ""):
        """One place where a client library's exceptions become this module's.

        Two translations, and both exist so no caller has to know which store
        it is talking to:

          * the duplicate-charge_id guard becomes ValueError, which is what
            the interface says and what the in-memory store raises;
          * everything else becomes TaskStateUnavailable, an OSError, which
            every existing call site already handles correctly.
        """
        try:
            return script(keys=keys, args=args)
        except Exception as exc:
            if "already in flight" in str(exc):
                raise ValueError(
                    f"charge_id already in flight: {charge_id!r}"
                ) from exc
            raise TaskStateUnavailable(str(exc)) from exc

    def charge(self, task_id: str, *, charge_id: str, rows: int,
               data_class: str | None, now: int, expires_at: int) -> dict:
        return self._decode(self._run(
            self._charge,
            keys=[self._key(task_id)],
            args=[now, charge_id, rows, data_class or "", expires_at,
                  self._max_in_flight],
            charge_id=charge_id,
        ))

    def reconcile(self, task_id: str, charge_id: str, *, rows: int,
                  data_class: str | None, now: int) -> None:
        if rows < 0:
            # In PYTHON, before the script is sent at all -- Redis does not
            # roll back a partially executed script, so validation that could
            # run after a write is not validation.
            raise ValueError(f"rows must be non-negative, got {rows}")
        self._run(
            self._reconcile,
            keys=[self._key(task_id)],
            args=[now, charge_id, rows, data_class or ""],
        )

    def release(self, task_id: str, charge_id: str, *, now: int) -> None:
        self._run(self._release, keys=[self._key(task_id)],
                  args=[now, charge_id, 0, ""])

    def abandon(self, task_id: str, charge_id: str, *,
                data_class: str | None, now: int) -> None:
        self._run(self._abandon, keys=[self._key(task_id)],
                  args=[now, charge_id, 0, data_class or ""])

    def peek(self, task_id: str, *, now: int) -> dict:
        return self._decode(
            self._run(self._peek, keys=[self._key(task_id)], args=[now])
        )
