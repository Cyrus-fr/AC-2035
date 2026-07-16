"""Pluggable kill-switch providers (U2).

Each Provider wraps one containment action against one external control plane.
The orchestrator loads the enabled providers dynamically from
killswitch/config.yaml, so adding a control plane never touches orchestrator
code — see killswitch/providers/base.py for the interface.
"""
