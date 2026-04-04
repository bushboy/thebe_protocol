"""Policy evaluation logic for Safety Agent.

This module implements policy evaluation against OPA and signing of approvals.

Requirements: 7.1, 7.2, 7.3, 7.5
"""

from datetime import datetime
from typing import List, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

from shared.schemas import PolicyDecision, IntentSignature
from shared.opa import OPAClient, OPAError
from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)


class TaskGraph(Dict[str, Any]):
    """Type alias for task graph structure."""
    pass


class PolicyEvaluator:
    """Evaluates actions against OPA policies and signs approvals.

    This class handles:
    - Validating requester identity
    - Querying OPA for policy decisions
    - Signing policy approvals
    - Including denial reasons

    Requirements: 7.1, 7.2, 7.3, 7.5
    """

    def __init__(self):
        """Initialize policy evaluator with OPA client and signing key."""
        self.opa_client = OPAClient(
            opa_url=config.opa_url,
            policy_path=config.opa_policy_path,
            timeout=config.opa_timeout
        )
        self._load_signing_key()

    def _load_signing_key(self):
        """Load private key for signing policy approvals."""
        try:
            with open(config.signing_key_path, "rb") as key_file:
                self.signing_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            logger.info("Signing key loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load signing key: {str(e)}")
            raise

    def validate_requester_identity(
        self,
        certificate_identity: str,
        jwt_claims: Dict[str, Any]
    ) -> bool:
        """Validate that the requester is authorized (Planner or Intent Engine).

        Args:
            certificate_identity: Identity from mTLS certificate
            jwt_claims: Claims from JWT token

        Returns:
            True if requester is authorized

        Requirements: 7.1
        """
        # Extract service name from certificate identity (e.g., "CN=planner")
        if "CN=" in certificate_identity:
            service_name = certificate_identity.split("CN=")[1].split(",")[0].strip()
        else:
            service_name = certificate_identity

        # Check if requester is Planner or Intent Engine
        authorized_services = ["planner", "intent-engine"]

        if service_name.lower() not in authorized_services:
            logger.warning(f"Unauthorized service attempted access: {service_name}")
            return False

        logger.info(f"Requester identity validated: {service_name}")
        return True

    def _is_known_safe_action(self, action: str, provider: str) -> bool:
        """Validate that an action is a known, safe action for the provider.

        This implements a whitelist of known safe actions to prevent arbitrary
        system commands or destructive operations from being executed.

        Args:
            action: The action to validate
            provider: The provider name (github, aws, gcp, azure, slack, google_workspace)

        Returns:
            True if the action is known and safe, False otherwise

        Requirements: 9.1, 13.2 (prompt injection defense)
        """
        # Define known safe actions per provider
        known_safe_actions = {
            "github": {
                "create_branch",
                "create_pr",
                "create_pull_request",
                "create_issue",
                "add_label",
                "add_assignee",
                "add_reviewer",
                "merge_pr",
                "merge_pull_request",
                "update_issue",
                "close_issue",
                "reopen_issue",
                "comment_on_issue",
                "comment_on_pr",
                "approve_review",
                "request_changes"
            },
            "aws": {
                "describe_instances",
                "describe_services",
                "list_objects",
                "read_logs"
            },
            "gcp": {
                "describe_instances",
                "list_resources",
                "read_logs"
            },
            "azure": {
                "describe_instances",
                "list_resources",
                "read_logs"
            },
            "slack": {
                "send_message",
                "post_message",
                "create_channel",
                "add_member",
                "update_channel_topic",
                "set_channel_description"
            },
            "google_workspace": {
                "create_document",
                "update_document",
                "share_document",
                "create_spreadsheet",
                "create_presentation"
            }
        }

        # Get known actions for this provider
        provider_actions = known_safe_actions.get(provider.lower(), set())

        if not provider_actions:
            # Unknown provider - use strict validation
            logger.warning(f"Unknown provider: {provider}")
            return False

        # Normalize action name
        action_lower = action.lower()

        # Check if action is in the whitelist
        if action_lower in provider_actions:
            return True

        logger.warning(f"Unknown action '{action}' for provider '{provider}'")
        return False

    def _check_for_dangerous_patterns(self, action: str) -> bool:
        """Check if an action contains dangerous patterns even if it claims to be safe.

        Args:
            action: The action to check

        Returns:
            True if any dangerous patterns are detected

        Requirements: 13.2, 13.3 (prompt injection defense)
        """
        action_lower = action.lower()

        # Dangerous patterns that should never be allowed
        dangerous_patterns = [
            "delete",
            "destroy",
            "wipe",
            "format",
            "remove_all",
            "erase",
            "purge",
            "terminate_service",
            "kill_process",
            "shutdown",
            "reboot",
            "halt",
            "poweroff",
            "rm_", "rmdir", "rm -r",
            "/home/deploy", "/home", "/root", "/etc", "/bin", "/sys"
        ]

        for pattern in dangerous_patterns:
            if pattern.lower() in action_lower:
                logger.warning(
                    f"Dangerous pattern '{pattern}' detected in action: {action}"
                )
                return True

        return False

    def _check_action_alignment(
        self,
        action: str,
        intent_signature: IntentSignature
    ) -> bool:
        """Check if an action aligns with the intent signature.

        This method verifies that the action is in the allowed_actions list
        of the intent signature, implementing prompt injection defense.

        Args:
            action: The action to check
            intent_signature: Intent signature with allowed actions

        Returns:
            True if action is aligned, False otherwise

        Requirements: 13.2, 13.3
        """
        if not intent_signature.allowed_actions:
            logger.warning("Intent signature has no allowed actions")
            return False

        # Check if action matches any allowed action
        # Support both exact matches and partial matches (e.g., "create_branch" in "github:create_branch")
        for allowed_action in intent_signature.allowed_actions:
            if action == allowed_action or action in allowed_action or allowed_action in action:
                return True

        return False

    def evaluate_task_graph(
        self,
        task_graph: List[TaskGraph],
        intent_signature: IntentSignature,
        context: Dict[str, Any]
    ) -> PolicyDecision:
        """Evaluate all tasks in the graph against OPA policies.

        Args:
            task_graph: List of tasks to evaluate
            intent_signature: Intent signature from Intent Engine
            context: Context including user_id, role, etc.

        Returns:
            PolicyDecision with ALLOW or DENY and signature

        Requirements: 7.2, 7.3, 7.5, 13.1, 13.2, 13.3
        """
        logger.info(f"Evaluating {len(task_graph)} tasks against policies")

        semantic_score = intent_signature.semantic_similarity_score
        semantic_threshold = (
            intent_signature.semantic_match_threshold
            if intent_signature.semantic_match_threshold is not None
            else 0.7
        )

        all_policies_passed = True
        evaluated_policies = []
        denial_reasons = []

        # Evaluate each task in the graph
        for task in task_graph:
            task_id = task.get("task_id", "unknown")
            action = task.get("action", "")
            provider = task.get("provider", "")

            logger.info(f"Evaluating task {task_id}: {action} on {provider}")

            # Check for dangerous patterns first (Requirement 13.2)
            if self._check_for_dangerous_patterns(action):
                all_policies_passed = False
                denial_reasons.append(
                    f"Action '{action}' contains dangerous patterns and is not allowed"
                )
                evaluated_policies.append(f"dangerous_patterns_check_{action}")
                logger.warning(f"Dangerous pattern detected in task {task_id}: {action}")
                continue

            # Validate that this is a known safe action (Requirement 13.2)
            if not self._is_known_safe_action(action, provider):
                all_policies_passed = False
                denial_reasons.append(
                    f"Action '{action}' is not a recognized safe action for provider '{provider}'"
                )
                evaluated_policies.append(f"unknown_action_check_{provider}_{action}")
                logger.warning(
                    f"Unknown/unsafe action detected for task {task_id}: "
                    f"{action} on {provider}"
                )
                continue

            # Check intent alignment (Requirement 13.3)
            # If action is not in allowed_actions, it's misaligned
            action_aligned = self._check_action_alignment(action, intent_signature)

            if not action_aligned:
                all_policies_passed = False
                if semantic_score is not None:
                    user_goal = context.get("user_goal", "original user goal")
                    denial_reasons.append(
                        f"Action blocked: '{action}' violates '{user_goal}' intent "
                        f"(semantic match {semantic_score:.2f} < threshold {semantic_threshold:.2f}); "
                        f"allowed actions: {intent_signature.allowed_actions}"
                    )
                else:
                    denial_reasons.append(
                        f"Action '{action}' does not match original intent - "
                        f"not in allowed actions: {intent_signature.allowed_actions}"
                    )
                evaluated_policies.append(f"intent_alignment_{action}")
                logger.warning(
                    f"Intent misalignment detected for task {task_id}: "
                    f"action '{action}' not in allowed actions"
                )
                continue

            # Construct OPA input
            opa_input = {
                "action": action,
                "provider": provider,
                "context": context,
                "action_category": task.get("action_category", "standard"),
                "intent_alignment_score": 1.0,  # Action is aligned if we reach here
                "estimated_cost": task.get("estimated_cost", 0.0),
                "action_params": task.get("action_params", {})
            }

            # Query OPA
            try:
                result = self.opa_client.evaluate(opa_input)

                # Track evaluated policies
                policy_name = f"{provider}_{action}"
                evaluated_policies.append(policy_name)

                if not result.allow:
                    all_policies_passed = False
                    denial_reasons.extend(result.deny_reasons)
                    logger.warning(
                        f"Policy denied task {task_id}: {', '.join(result.deny_reasons)}"
                    )
                else:
                    logger.info(f"Policy allowed task {task_id}")

            except OPAError as e:
                logger.error(f"OPA evaluation failed for task {task_id}: {str(e)}")
                all_policies_passed = False
                denial_reasons.append(f"Policy evaluation error: {str(e)}")

        # Determine final decision
        if all_policies_passed:
            decision = "ALLOW"
            reason = "All policies passed"
        else:
            decision = "DENY"
            reason = "; ".join(denial_reasons)

        # Create policy decision
        policy_decision = PolicyDecision(
            decision=decision,
            reason=reason,
            evaluated_policies=evaluated_policies,
            semantic_similarity_score=semantic_score,
            semantic_match_threshold=semantic_threshold,
            signature="",  # Will be filled by sign_approval
            timestamp=datetime.utcnow(),
            signer_identity=config.service_name
        )

        # Sign the approval
        signed_decision = self.sign_approval(policy_decision)

        logger.info(f"Policy evaluation complete: {decision}")
        return signed_decision

    def sign_approval(self, policy_decision: PolicyDecision) -> PolicyDecision:
        """Generate cryptographic signature for policy decision.

        Args:
            policy_decision: Policy decision to sign

        Returns:
            PolicyDecision with signature field populated

        Requirements: 7.3
        """
        # Create message to sign (deterministic representation)
        message_parts = [
            policy_decision.decision,
            policy_decision.reason,
            ",".join(sorted(policy_decision.evaluated_policies)),
            (
                f"{policy_decision.semantic_similarity_score:.6f}"
                if policy_decision.semantic_similarity_score is not None
                else ""
            ),
            (
                f"{policy_decision.semantic_match_threshold:.6f}"
                if policy_decision.semantic_match_threshold is not None
                else ""
            ),
            policy_decision.timestamp.isoformat(),
            policy_decision.signer_identity
        ]
        message = "|".join(message_parts).encode("utf-8")

        # Sign with private key
        try:
            signature_bytes = self.signing_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Encode signature as base64
            signature = base64.b64encode(signature_bytes).decode("utf-8")

            # Update policy decision with signature
            policy_decision.signature = signature

            logger.info("Policy approval signed successfully")
            return policy_decision

        except Exception as e:
            logger.error(f"Failed to sign policy approval: {str(e)}")
            raise
