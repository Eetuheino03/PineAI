#!/usr/bin/env python3

"""PineAI module backend."""

import logging

from pineapple.modules import Module, Request


module = Module("PineAI", logging.INFO)


@module.handles_action("health")
def health(_request: Request):
    """Return a small response used to verify frontend/backend communication."""
    return {
        "status": "ok",
        "module": "PineAI",
        "version": "0.1.0",
    }


if __name__ == "__main__":
    module.start()
