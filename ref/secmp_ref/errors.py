# SPDX-License-Identifier: AGPL-3.0-or-later
"""The uniform rejection error (spec §1.1 goal 6 "fail closed", §7.4 note (b), Appendix C)."""


class Reject(Exception):
    """Raised for every verification or input-validation failure on untrusted data.

    It deliberately carries no detail, so that no caller (and no test vector) can tell one
    failure cause from another. Programming errors (wrong argument types or lengths of values
    this implementation produced itself) raise ValueError instead.
    """

    def __init__(self):
        super().__init__("reject")
