"""Task graph generation module for Planner service.

This module generates task execution graphs from user goals and context.

Requirements: 5.3
"""

import uuid
import asyncio
from typing import List, Dict, Any
from shared.logging import JSONLogger
from shared.pendo import track_event


logger = JSONLogger(__name__)


class TaskGraphItem:
    """Represents a single task in the execution graph."""

    def __init__(
        self,
        task_id: str,
        action: str,
        provider: str,
        dependencies: List[str] = None
    ):
        """Initialize task graph item.

        Args:
            task_id: Unique task identifier
            action: Action to be performed
            provider: Target provider (github, slack, google_workspace)
            dependencies: List of task IDs this task depends on
        """
        self.task_id = task_id
        self.action = action
        self.provider = provider
        self.dependencies = dependencies or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary representation."""
        return {
            "task_id": self.task_id,
            "action": self.action,
            "provider": self.provider,
            "dependencies": self.dependencies
        }


class TaskGraphGenerator:
    """Generates task execution graphs from user goals."""

    def __init__(self):
        """Initialize task graph generator."""
        pass

    def generate_task_graph(
        self,
        user_goal: str,
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate task execution graph from user goal.

        This is a simplified implementation that parses the user goal
        and generates a basic task graph. In a production system, this
        would use more sophisticated NLP and planning algorithms.

        Args:
            user_goal: User's stated goal
            context: Context including role, allowed_providers, etc.

        Returns:
            List of task dictionaries representing the execution graph

        Raises:
            ValueError: If goal contains destructive keywords or cannot be safely mapped

        Requirements: 5.3, 13.2 (prevent destructive operations)
        """
        logger.info(f"Generating task graph for goal: {user_goal[:100]}...")

        # Extract allowed providers from context
        allowed_providers = context.get("allowed_providers", ["github", "slack", "google_workspace"])

        # Check for destructive keywords FIRST - before any processing
        # Requirement 13.2: Detect and reject destructive operations
        goal_lower = user_goal.lower()

        destructive_keywords = [
            "delete", "wipe", "destroy", "erase", "format", "purge",
            "remove all", "recursively remove", "rm -rf", "rm -", "drop table", "truncate",
            "uninstall", "terminate", "kill", "shutdown", "reboot", "halt"
        ]

        for keyword in destructive_keywords:
            if keyword in goal_lower:
                error_msg = (
                    f"Goal contains destructive intent and will not be planned: '{user_goal[:100]}'. "
                    f"Guardian does not execute destructive operations through the Planner."
                )
                logger.warning(error_msg)

                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(track_event(
                        "task_plan_blocked",
                        properties={
                            "block_reason": error_msg[:200],
                            "block_type": "destructive_keyword",
                            "goal_length": len(user_goal),
                            "detected_keyword": keyword,
                        },
                    ))
                except RuntimeError:
                    pass

                raise ValueError(error_msg)

        # Explicitly reject tenant-scoped support-data retrieval/exfiltration goals.
        # These requests can be sensitive even when non-destructive.
        sensitive_data_patterns = [
            "support ticket",
            "support tickets",
            "tenant id",
            "tenant-",
            "all tickets",
            "retrieve all",
            "summarise all customer",
            "summarise all ticket",
            "share with our team",
            "customer tickets",
            "export tickets"
        ]

        if any(pattern in goal_lower for pattern in sensitive_data_patterns):
            error_msg = (
                f"Goal requests sensitive tenant-scoped support data and will not be planned: '{user_goal[:100]}'. "
                "Guardian requires explicit, policy-approved workflows for tenant data access."
            )
            logger.warning(error_msg)

            detected = next((p for p in sensitive_data_patterns if p in goal_lower), "")
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(track_event(
                    "task_plan_blocked",
                    properties={
                        "block_reason": error_msg[:200],
                        "block_type": "sensitive_data_pattern",
                        "goal_length": len(user_goal),
                        "detected_keyword": detected,
                    },
                ))
            except RuntimeError:
                pass

            raise ValueError(error_msg)

        # Simple keyword-based task generation
        # In production, this would use NLP and more sophisticated planning
        tasks = []

        # GitHub actions
        if "github" in allowed_providers:
            if "create branch" in goal_lower or "new branch" in goal_lower:
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="create_branch",
                    provider="github"
                ))

            if "create pr" in goal_lower or "pull request" in goal_lower:
                # PR creation depends on branch creation if both are present
                dependencies = [tasks[-1].task_id] if tasks else []
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="create_pr",
                    provider="github",
                    dependencies=dependencies
                ))

            if "list repo" in goal_lower or "show repo" in goal_lower:
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="list_repos",
                    provider="github"
                ))

            if ("list" in goal_lower and "issue" in goal_lower) or \
               ("fetch" in goal_lower and "issue" in goal_lower):
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="list_issues",
                    provider="github"
                ))

            if "add label" in goal_lower or "add the label" in goal_lower:
                dependencies = [tasks[-1].task_id] if tasks else []
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="add_label",
                    provider="github",
                    dependencies=dependencies
                ))

        # Slack actions
        if "slack" in allowed_providers:
            if "send message" in goal_lower or "post message" in goal_lower or \
               "post a message" in goal_lower or "notify" in goal_lower or \
               "post to" in goal_lower:
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="send_message",
                    provider="slack"
                ))

            if "list channel" in goal_lower or "show channel" in goal_lower:
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="list_channels",
                    provider="slack"
                ))

        # CI / filesystem actions (provider-agnostic)
        if ("ci" in goal_lower and "log" in goal_lower) or "build log" in goal_lower:
            tasks.append(TaskGraphItem(
                task_id=str(uuid.uuid4()),
                action="read_ci_logs",
                provider="ci"
            ))

        if ("write" in goal_lower and ".md" in goal_lower) or \
           ("write" in goal_lower and "summary" in goal_lower):
            dependencies = [tasks[-1].task_id] if tasks else []
            tasks.append(TaskGraphItem(
                task_id=str(uuid.uuid4()),
                action="write_file",
                provider="filesystem",
                dependencies=dependencies
            ))

        # Google Workspace actions
        if "google_workspace" in allowed_providers:
            if "send email" in goal_lower or "email" in goal_lower:
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="send_email",
                    provider="google_workspace"
                ))

            if "create doc" in goal_lower or "new document" in goal_lower:
                tasks.append(TaskGraphItem(
                    task_id=str(uuid.uuid4()),
                    action="create_doc",
                    provider="google_workspace"
                ))

        # If no specific actions detected, REJECT instead of silent fallback
        # Requirement 13.2: Refuse to plan unrecognized or potentially unintended goals
        if not tasks:
            error_msg = (
                f"Goal could not be mapped to any known safe action: '{user_goal[:100]}'. "
                "Guardian requires goals to explicitly specify supported actions "
                "(e.g., 'create a branch', 'send a message', 'create a document'). "
                "Refusing to generate a plan for an ambiguous or unrecognized goal."
            )
            logger.warning(error_msg)

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(track_event(
                    "task_plan_blocked",
                    properties={
                        "block_reason": error_msg[:200],
                        "block_type": "unrecognized_goal",
                        "goal_length": len(user_goal),
                        "detected_keyword": "",
                    },
                ))
            except RuntimeError:
                pass

            raise ValueError(error_msg)

        # Convert to dictionary format
        task_graph = [task.to_dict() for task in tasks]

        logger.info(f"Generated task graph with {len(task_graph)} tasks")

        return task_graph
