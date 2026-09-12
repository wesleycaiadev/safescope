"""Controlled active scanners; never included in default public jobs."""

from .authorization import AuthorizationCandidate, AuthorizationMatrixScanner, IdorScanner

RAZOR_SCANNERS = (IdorScanner, AuthorizationMatrixScanner)

__all__ = [
    "RAZOR_SCANNERS",
    "AuthorizationCandidate",
    "AuthorizationMatrixScanner",
    "IdorScanner",
]
