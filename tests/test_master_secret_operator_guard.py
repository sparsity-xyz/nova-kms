"""Regression tests: non-operator nodes must never generate/sync the master secret.

NOTE: The original ``wait_for_master_secret`` method was removed as dead code
(audit finding C2).  Its logic is now part of ``node_tick``.
The operator-guard invariant is tested transitively in ``test_sync.py``
(see ``TestNodeTick``).
"""
