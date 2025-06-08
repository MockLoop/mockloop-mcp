"""
SchemaPin Policy Enforcement Module

Handles security policy evaluation and enforcement decisions.
"""


from .config import PolicyAction, PolicyDecision, SchemaPinConfig, VerificationResult


class PolicyHandler:
    """Handles SchemaPin verification policy enforcement."""

    def __init__(self, config: SchemaPinConfig):
        """Initialize policy handler with configuration."""
        self.config = config
        self.policy_overrides: dict[str, str] = {}  # Tool-specific policy overrides

    async def evaluate_verification_result(self, result: VerificationResult,
                                         tool_name: str) -> PolicyDecision:
        """
        Evaluate verification result against configured policies.

        Args:
            result: Verification result to evaluate
            tool_name: Name of the tool being verified

        Returns:
            Policy decision with action and reasoning
        """
        # Check for tool-specific policy overrides
        effective_policy = self.policy_overrides.get(tool_name, self.config.policy_mode)

        if not result.valid:
            if effective_policy == "enforce":
                return PolicyDecision(
                    action=PolicyAction.BLOCK,
                    reason=f"Schema verification failed: {result.error}",
                    policy_mode=effective_policy
                )
            elif effective_policy == "warn":
                return PolicyDecision(
                    action=PolicyAction.WARN,
                    reason=f"Schema verification failed: {result.error}",
                    policy_mode=effective_policy
                )
            else:  # log mode
                return PolicyDecision(
                    action=PolicyAction.LOG,
                    reason=f"Schema verification failed: {result.error}",
                    policy_mode=effective_policy
                )

        # Handle successful verification
        if result.key_pinned or self.should_auto_pin_key(result.domain, result.tool_id):
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="Schema verification successful",
                policy_mode=effective_policy
            )

        # Handle TOFU scenario
        if self.config.interactive_mode:
            return PolicyDecision(
                action=PolicyAction.PROMPT,
                reason="New key requires user confirmation",
                policy_mode=effective_policy
            )
        else:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="Auto-pinning new key",
                policy_mode=effective_policy
            )

    def should_auto_pin_key(self, domain: str | None, _tool_id: str) -> bool:
        """
        Determine if key should be auto-pinned.

        Args:
            domain: Domain the key belongs to
            tool_id: Tool identifier

        Returns:
            True if key should be auto-pinned, False otherwise
        """
        if self.config.auto_pin_keys:
            return True

        if domain and domain in self.config.trusted_domains:
            return True

        return False

    def is_trusted_domain(self, domain: str) -> bool:
        """
        Check if domain is in trusted list.

        Args:
            domain: Domain to check

        Returns:
            True if domain is trusted, False otherwise
        """
        return domain in self.config.trusted_domains

    def set_policy_override(self, tool_name: str, policy_mode: str) -> None:
        """
        Set tool-specific policy override.

        Args:
            tool_name: Name of the tool
            policy_mode: Policy mode to override with
        """
        valid_modes = ["enforce", "warn", "log"]
        if policy_mode not in valid_modes:
            raise ValueError(f"Invalid policy mode: {policy_mode}. Must be one of {valid_modes}")

        self.policy_overrides[tool_name] = policy_mode

    def remove_policy_override(self, tool_name: str) -> None:
        """
        Remove tool-specific policy override.

        Args:
            tool_name: Name of the tool
        """
        self.policy_overrides.pop(tool_name, None)

    def get_effective_policy(self, tool_name: str) -> str:
        """
        Get effective policy for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Effective policy mode
        """
        return self.policy_overrides.get(tool_name, self.config.policy_mode)

    def list_policy_overrides(self) -> dict[str, str]:
        """
        List all policy overrides.

        Returns:
            Dictionary of tool names to policy modes
        """
        return self.policy_overrides.copy()
