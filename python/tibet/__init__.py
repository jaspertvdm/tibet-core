"""
TIBET Core - The Linux of AI Provenance

Transaction/Interaction-Based Evidence Trail

A minimal, embeddable provenance engine for any device.
From microcontrollers to cloud servers.

Quick Start:
    from tibet_core import TibetEngine

    engine = TibetEngine()
    token = engine.create_token(
        token_type="action",
        erin="User requested translation",
        eraan=["model_v1", "tokenizer_v2"],
        eromheen='{"env": "production"}',
        erachter="Fulfilling user request",
        actor="agent_001"
    )

    print(token.id)
    print(token.verify())  # True

IETF Draft: https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/

Credits:
    - Specification: Jasper van de Meent (Humotica)
    - Implementation: Root AI (Claude) & Jasper
"""

from tibet_core import TibetEngine, TibetToken, __version__

__all__ = ["TibetEngine", "TibetToken", "__version__"]
