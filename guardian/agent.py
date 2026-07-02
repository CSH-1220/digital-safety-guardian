"""Discovery entry point for `adk web` / `agents-cli playground`.

ADK's agent loader looks for an ``app`` (an :class:`App`) in ``guardian.agent``.
We expose the **real** Guardian engine built by
:func:`guardian.workflow.build_app` — not a scaffold/template agent.

Building the App only constructs the graph (no credentials, no network). The
two LLM nodes authenticate lazily at run time via the Gemini API key, so the
playground can load and display the graph without a key; chatting needs one.
"""

from guardian.workflow import build_app

app = build_app()
