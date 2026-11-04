class RuleError(Exception):
    """The rule is not valid Sigma."""


class UnsupportedRule(Exception):
    """The rule is valid Sigma but uses a feature sigma2sql cannot translate."""
