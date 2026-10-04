"""
Typed errors with stable codes.

Backend endpoints raise `api_error(code, **context)` instead of a
localised string. The frontend translates the code via i18n using
`context` as interpolation values.

Codes follow the shape "<domain>.<snake_case_short_name>", for example:
    auth.invalid_credentials
    agent.key_in_use
    validation.email_invalid
"""

from typing import Any

from fastapi import HTTPException, status


def api_error(
    status_code: int,
    code: str,
    **context: Any,
) -> HTTPException:
    """
    Build an HTTPException whose `detail` is either:
      - the plain string `code` when no context is provided
      - a dict {"code": ..., "context": {...}} otherwise

    The frontend translator handles both shapes.
    """
    if context:
        detail: Any = {"code": code, "context": context}
    else:
        detail = code
    return HTTPException(status_code=status_code, detail=detail)
