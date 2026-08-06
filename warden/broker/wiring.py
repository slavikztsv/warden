"""The components both enforcement surfaces share, as a type rather than a dict.

build() used to return an untyped dict splatted into create_app AND
serve_proxy. Their signatures differ and neither takes **kwargs, so every key
had to be a valid keyword of both -- and adding the catalog, which the tool
API needs and the proxy does not, raised TypeError from serve_proxy and took
all egress down. Nothing greppable expressed that constraint.
"""

from __future__ import annotations

from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass

DEFAULT_WORKER_THREADS = 16


def build_executor(worker_threads: int = DEFAULT_WORKER_THREADS) -> ThreadPoolExecutor:
    """The one pool both enforcement surfaces run the spine on.

    Named threads, because a stuck broker's stack dump should say which
    subsystem is stuck rather than "ThreadPoolExecutor-0_7".
    """
    return ThreadPoolExecutor(
        max_workers=worker_threads, thread_name_prefix="warden-spine"
    )


@dataclass(frozen=True)
class BrokerComponents:
    verifier: object
    pdp: object
    task_state: object
    audit: object
    policy_digest: str
    # Deliberately absent from BOTH kwargs methods below, and that is the
    # whole reason it is a field rather than something the caller carries
    # separately: those dicts are splatted into serve_proxy, which forwards
    # them verbatim into authorize_connect -- keyword-only, no **kwargs -- so
    # a new key reaching them raises TypeError inside EVERY CONNECT, at
    # request time, with the broker still reporting healthy. That is the
    # exact incident this module's docstring records. serve_proxy takes the
    # executor as its own named parameter instead.
    #
    # Annotated, unlike the four fields above it. Those carry P1's untyped
    # debt (F1b in the roadmap); a new field does not get to add to it.
    executor: Executor | None = None

    def as_app_kwargs(self) -> dict:
        return {
            "verifier": self.verifier, "pdp": self.pdp,
            "task_state": self.task_state,
            "audit": self.audit, "policy_digest": self.policy_digest,
        }

    def as_proxy_kwargs(self) -> dict:
        return self.as_app_kwargs()
