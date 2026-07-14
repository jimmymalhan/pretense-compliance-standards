"""
pretense_compliance_standards — the Pretense compliance standard.

A graded, fully-synthetic testbed that scores sensitive-data detection across a
difficulty gradient AND across the major global compliance frameworks (SOC2,
ISO 27001, NIST, FedRAMP, HIPAA/HITECH, GDPR, CCPA, LGPD, DORA, PCI DSS, and
more), and — via the pretense.ai bridge — how well the pretense firewall's
identify + mutate protects each framework's data.

Everything in this package is SYNTHETIC. Every "sensitive" value is fake by
construction (SSNs in the never-issued 900-xx-xxxx range, 555-01xx phone
numbers reserved for fiction, example.com emails, the published AWS *example*
key, Luhn-valid but bogus card numbers, sk_test_ API keys). No value maps to a
real person, account, or secret.

Purpose: measure how well a DLP detector CATCHES sensitive data across a
difficulty gradient (easy -> hard). The corpus ships ground-truth labels
(`expected: should be flagged`); the harness runs a detector over it and reports
recall per tier. A case the detector misses is a bug to fix in the detector, not
a way to evade a control. The benchmark exists to raise recall.
"""

from __future__ import annotations

__all__ = ["generator", "detector", "corpus_builder", "harness"]

BANNER = "SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL"
