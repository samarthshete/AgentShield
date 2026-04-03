# Architecture

AgentShield Phase 1 is a scanner-first architecture:

CLI → parser → static rules → severity scoring → reports → SQLite persistence

Why this architecture:
- fast to build
- easy to explain
- useful before dynamic simulation exists
- strong enough for GitHub and early resume signal
