"""Rich Authorization Request (RAR) construction for Permission Broker.

This module constructs Rich Authorization Requests for provider token requests.
RAR includes action type, scopes, locations, purpose, and context.

Requirements: 8.4, 1.7
"""

from typing import Dict, Any, List

from shared.schemas import RichAuthorizationRequest
from shared.logging import JSONLogger
from shared.scopes import ScopeCategorizer, ScopeCategory


logger = JSONLogger(__name__)


# Action to scope category mapping
# Maps specific actions to their required scope category
ACTION_SCOPE_MAPPING = {
    "github": {
        "list_repos": ScopeCategory.READ_ONLY,
        "get_repo": ScopeCategory.READ_ONLY,
        "create_branch": ScopeCategory.WRITE_ACTION,
        "create_pr": ScopeCategory.WRITE_ACTION,
        "merge_pr": ScopeCategory.WRITE_ACTION,
        "delete_branch": ScopeCategory.WRITE_ACTION,
        "delete_repo": ScopeCategory.WRITE_ACTION
    },
    "slack": {
        "list_channels": ScopeCategory.READ_ONLY,
        "get_channel": ScopeCategory.READ_ONLY,
        "send_message": ScopeCategory.WRITE_ACTION,
        "create_channel": ScopeCategory.WRITE_ACTION,
        "delete_channel": ScopeCategory.WRITE_ACTION
    },
    "google_workspace": {
        "list_emails": ScopeCategory.READ_ONLY,
        "read_email": ScopeCategory.READ_ONLY,
        "send_email": ScopeCategory.WRITE_ACTION,
        "create_doc": ScopeCategory.WRITE_ACTION,
        "delete_user": ScopeCategory.WRITE_ACTION
    }
}


# Action to minimal required scopes mapping.
# This allows least-privilege scope requests for individual operations.
ACTION_REQUIRED_SCOPES = {
    "github": {
        "list_repos": ["repo:read"],
        "get_repo": ["repo:read"],
        "create_branch": ["repo:write"],
        "create_pr": ["repo:write"],
        "merge_pr": ["repo:write"],
        "delete_branch": ["repo:write"],
        "delete_repo": ["delete_repo"]
    },
    "slack": {
        "list_channels": ["channels:read"],
        "get_channel": ["channels:read"],
        "send_message": ["chat:write"],
        "create_channel": ["channels:manage"],
        "delete_channel": ["channels:manage"]
    },
    "google_workspace": {
        "list_emails": ["https://www.googleapis.com/auth/gmail.readonly"],
        "read_email": ["https://www.googleapis.com/auth/gmail.readonly"],
        "send_email": ["https://www.googleapis.com/auth/gmail.send"],
        "create_doc": ["https://www.googleapis.com/auth/drive"],
        "delete_user": ["https://www.googleapis.com/auth/drive"]
    }
}


class RARConstructor:
    """Constructs Rich Authorization Requests for provider tokens."""

    def construct_rar(
        self,
        provider: str,
        action: str,
        plan_id: str,
        task_id: str,
        intent_hash: str,
        action_params: Dict[str, Any]
    ) -> RichAuthorizationRequest:
        """Construct a Rich Authorization Request.

        Args:
            provider: Target provider (github, slack, google_workspace)
            action: Action to be performed
            plan_id: Unique plan identifier
            task_id: Unique task identifier
            intent_hash: Hash from intent signature
            action_params: Action-specific parameters

        Returns:
            RichAuthorizationRequest object

        Requirements: 8.4
        """
        logger.info(f"Constructing RAR for provider: {provider}, action: {action}")

        # Determine action type
        action_type = f"{provider}_action"

        # Determine required scopes based on action
        scopes = self._determine_scopes(provider, action)

        # Determine resource locations
        locations = self._determine_locations(provider, action_params)

        # Set purpose
        purpose = "task_execution"

        # Build context
        context = {
            "plan_id": plan_id,
            "task_id": task_id,
            "intent_hash": intent_hash,
            "action": action,
            "provider": provider
        }

        # Add action-specific context
        if action_params:
            context["action_params"] = action_params

        rar = RichAuthorizationRequest(
            type=action_type,
            actions=scopes,
            locations=locations,
            purpose=purpose,
            context=context
        )

        logger.info(f"RAR constructed with {len(scopes)} scopes and {len(locations)} locations")

        return rar

    def validate_requested_scopes(
        self,
        provider: str,
        requested_scopes: List[str]
    ) -> Dict[str, List[str]]:
        """Validate requested scopes against provider scope categories.

        This method enforces scope distinctions by validating that requested
        scopes are recognized and properly categorized.

        Args:
            provider: Target provider
            requested_scopes: List of requested scopes

        Returns:
            Dictionary with categorized scopes:
            {
                "read_only": [...],
                "write_action": [...],
                "invalid": [...]
            }

        Requirements: 1.7
        """
        logger.info(f"Validating {len(requested_scopes)} requested scopes for {provider}")

        categorized = ScopeCategorizer.validate_scopes(provider, requested_scopes)

        if categorized["invalid"]:
            logger.warning(
                f"Found {len(categorized['invalid'])} invalid scopes for {provider}: "
                f"{categorized['invalid']}"
            )

        return categorized

    def _determine_scopes(self, provider: str, action: str) -> List[str]:
        """Determine required OAuth scopes for the action.

        This method enforces scope distinctions by categorizing actions as
        read-only or write-action and returning appropriate scopes.

        Args:
            provider: Target provider
            action: Action to be performed

        Returns:
            List of required OAuth scopes

        Requirements: 1.7
        """
        # Prefer exact action-to-scope mapping to avoid over-requesting scopes.
        provider_required_scopes = ACTION_REQUIRED_SCOPES.get(provider, {})
        explicit_scopes = provider_required_scopes.get(action)
        if explicit_scopes:
            logger.info(
                f"Using explicit scope mapping for {provider}:{action} with "
                f"{len(explicit_scopes)} scopes"
            )
            return explicit_scopes

        # Get scope category for action
        action_mapping = ACTION_SCOPE_MAPPING.get(provider, {})
        scope_category = action_mapping.get(action)

        # If action not found in provider mapping, infer from action name
        if not scope_category:
            if any(keyword in action.lower() for keyword in ["list", "get", "read", "view"]):
                scope_category = ScopeCategory.READ_ONLY
            elif any(keyword in action.lower() for keyword in ["delete", "remove", "destroy"]):
                scope_category = ScopeCategory.WRITE_ACTION
            else:
                # Default to write for create/update/send actions
                scope_category = ScopeCategory.WRITE_ACTION

        # Get scopes for category using ScopeCategorizer
        try:
            scopes = ScopeCategorizer.get_scopes_for_category(provider, scope_category)

            if not scopes:
                logger.warning(
                    f"No scopes found for {provider}:{action} in category {scope_category.value}, "
                    f"falling back to read-only scopes"
                )
                scopes = ScopeCategorizer.get_scopes_for_category(provider, ScopeCategory.READ_ONLY)

            logger.info(
                f"Determined {len(scopes)} {scope_category.value} scopes for {provider}:{action}"
            )

            return scopes

        except ValueError as e:
            logger.error(f"Failed to determine scopes for {provider}:{action}: {e}")
            # Return empty list if provider not supported
            return []

    def _determine_locations(
        self,
        provider: str,
        action_params: Dict[str, Any]
    ) -> List[str]:
        """Determine resource locations for the action.

        Args:
            provider: Target provider
            action_params: Action-specific parameters

        Returns:
            List of resource URLs
        """
        locations = []

        if provider == "github":
            # Extract repository information
            repo = action_params.get("repository")
            org = action_params.get("organization")

            if repo and org:
                locations.append(f"https://github.com/{org}/{repo}")
            elif repo:
                locations.append(f"https://github.com/*/{repo}")
            else:
                locations.append("https://github.com/*")

        elif provider == "slack":
            # Extract workspace/channel information
            workspace = action_params.get("workspace")
            channel = action_params.get("channel")

            if workspace and channel:
                locations.append(f"https://{workspace}.slack.com/channels/{channel}")
            elif workspace:
                locations.append(f"https://{workspace}.slack.com/*")
            else:
                locations.append("https://*.slack.com/*")

        elif provider == "google_workspace":
            # Extract Google Workspace resource information
            domain = action_params.get("domain")
            resource_type = action_params.get("resource_type", "gmail")

            if domain:
                locations.append(f"https://www.googleapis.com/{resource_type}/{domain}/*")
            else:
                locations.append(f"https://www.googleapis.com/{resource_type}/*")

        # If no specific locations determined, use provider base URL
        if not locations:
            base_urls = {
                "github": "https://api.github.com/*",
                "slack": "https://slack.com/api/*",
                "google_workspace": "https://www.googleapis.com/*"
            }
            locations.append(base_urls.get(provider, "*"))

        return locations
