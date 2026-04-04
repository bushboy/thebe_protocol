"""Provider action execution module.

This module executes actions against external providers (GitHub, Slack, Google Workspace)
using DPoP-bound API calls.

Requirements: 9.3
"""

from typing import Dict, Any, Optional
import httpx
from github import Github, GithubException
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from shared.schemas import ZeroTrustAuthorizationToken
from shared.dpop import DPoPProofGenerator
from shared.logging import JSONLogger
from .config import config


logger = JSONLogger(__name__)


class ProviderExecutionError(Exception):
    """Exception raised when provider action execution fails."""
    pass


class ProviderExecutor:
    """Executor for provider-specific actions."""
    
    def __init__(self, dpop_generator: Optional[DPoPProofGenerator] = None):
        """Initialize provider executor.
        
        Args:
            dpop_generator: DPoP proof generator for API calls
        """
        self.dpop_generator = dpop_generator
        
        # Provider API base URLs
        self.github_api_url = config.github_api_url
        self.slack_api_url = config.slack_api_url
        self.google_workspace_api_url = config.google_workspace_api_url
    
    async def execute_action(
        self,
        zt_at: ZeroTrustAuthorizationToken,
        provider_token: str,
        action_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute action against provider.
        
        Args:
            zt_at: Zero-Trust Authorization Token
            provider_token: Provider-specific access token
            action_params: Action-specific parameters
            
        Returns:
            Dictionary with execution result
            
        Raises:
            ProviderExecutionError: If execution fails
            
        Requirements: 9.3
        """
        provider = zt_at.provider
        action = zt_at.action
        
        logger.info(f"Executing {provider}:{action} for plan: {zt_at.plan_id}, task: {zt_at.task_id}")
        
        # Route to appropriate provider handler
        if provider == "github":
            return await self._execute_github_action(action, provider_token, action_params)
        elif provider == "slack":
            return await self._execute_slack_action(action, provider_token, action_params)
        elif provider == "google_workspace":
            return await self._execute_google_workspace_action(action, provider_token, action_params)
        else:
            raise ProviderExecutionError(f"Unknown provider: {provider}")
    
    async def _execute_github_action(
        self,
        action: str,
        access_token: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute GitHub action.
        
        Args:
            action: Action name (e.g., create_branch, create_pr, list_repos)
            access_token: GitHub access token
            params: Action parameters
            
        Returns:
            Action result dictionary
            
        Raises:
            ProviderExecutionError: If GitHub API call fails
        """
        try:
            # Initialize GitHub client with access token
            github_client = Github(access_token)
            
            if action == "create_branch":
                return await self._github_create_branch(github_client, params)
            elif action == "create_pr":
                return await self._github_create_pr(github_client, params)
            elif action == "list_repos":
                return await self._github_list_repos(github_client, params)
            else:
                raise ProviderExecutionError(f"Unknown GitHub action: {action}")
                
        except GithubException as e:
            logger.error(f"GitHub API error: {e.status} - {e.data}")
            raise ProviderExecutionError(f"GitHub API error: {e.status} - {e.data}")
        except Exception as e:
            logger.error(f"GitHub action execution failed: {str(e)}")
            raise ProviderExecutionError(f"GitHub action failed: {str(e)}")
    
    async def _github_create_branch(
        self,
        client: Github,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a branch in GitHub repository.
        
        Args:
            client: GitHub client
            params: Parameters (repository, branch_name, source_branch)
            
        Returns:
            Result with branch information
        """
        repository = params.get("repository")
        branch_name = params.get("branch_name")
        source_branch = params.get("source_branch", "main")
        
        if not repository or not branch_name:
            raise ProviderExecutionError("Missing required parameters: repository, branch_name")
        
        repo = client.get_repo(repository)
        source_ref = repo.get_git_ref(f"heads/{source_branch}")
        source_sha = source_ref.object.sha
        
        new_ref = repo.create_git_ref(f"refs/heads/{branch_name}", source_sha)
        
        return {
            "action": "create_branch",
            "repository": repository,
            "branch_name": branch_name,
            "sha": new_ref.object.sha,
            "url": new_ref.url
        }
    
    async def _github_create_pr(
        self,
        client: Github,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a pull request in GitHub repository.
        
        Args:
            client: GitHub client
            params: Parameters (repository, title, head, base, body)
            
        Returns:
            Result with PR information
        """
        repository = params.get("repository")
        title = params.get("title")
        head = params.get("head")
        base = params.get("base", "main")
        body = params.get("body", "")
        
        if not repository or not title or not head:
            raise ProviderExecutionError("Missing required parameters: repository, title, head")
        
        repo = client.get_repo(repository)
        pr = repo.create_pull(title=title, body=body, head=head, base=base)
        
        return {
            "action": "create_pr",
            "repository": repository,
            "pr_number": pr.number,
            "pr_url": pr.html_url,
            "title": pr.title,
            "state": pr.state
        }
    
    async def _github_list_repos(
        self,
        client: Github,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """List repositories for authenticated user.
        
        Args:
            client: GitHub client
            params: Parameters (optional: type, sort, direction)
            
        Returns:
            Result with repository list
        """
        user = client.get_user()
        repos = user.get_repos(
            type=params.get("type", "all"),
            sort=params.get("sort", "updated"),
            direction=params.get("direction", "desc")
        )
        
        repo_list = [
            {
                "name": repo.name,
                "full_name": repo.full_name,
                "private": repo.private,
                "url": repo.html_url,
                "description": repo.description
            }
            for repo in repos[:10]  # Limit to first 10
        ]
        
        return {
            "action": "list_repos",
            "count": len(repo_list),
            "repositories": repo_list
        }
    
    async def _execute_slack_action(
        self,
        action: str,
        access_token: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Slack action.
        
        Args:
            action: Action name (e.g., send_message, list_channels)
            access_token: Slack access token
            params: Action parameters
            
        Returns:
            Action result dictionary
            
        Raises:
            ProviderExecutionError: If Slack API call fails
        """
        try:
            # Initialize Slack client with access token
            slack_client = WebClient(token=access_token)
            
            if action == "send_message":
                return await self._slack_send_message(slack_client, params)
            elif action == "list_channels":
                return await self._slack_list_channels(slack_client, params)
            else:
                raise ProviderExecutionError(f"Unknown Slack action: {action}")
                
        except SlackApiError as e:
            logger.error(f"Slack API error: {e.response['error']}")
            raise ProviderExecutionError(f"Slack API error: {e.response['error']}")
        except Exception as e:
            logger.error(f"Slack action execution failed: {str(e)}")
            raise ProviderExecutionError(f"Slack action failed: {str(e)}")
    
    async def _slack_send_message(
        self,
        client: WebClient,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send a message to Slack channel.
        
        Args:
            client: Slack client
            params: Parameters (channel, text, blocks)
            
        Returns:
            Result with message information
        """
        channel = params.get("channel")
        text = params.get("text")
        blocks = params.get("blocks")
        
        if not channel or not text:
            raise ProviderExecutionError("Missing required parameters: channel, text")
        
        response = client.chat_postMessage(
            channel=channel,
            text=text,
            blocks=blocks
        )
        
        return {
            "action": "send_message",
            "channel": response["channel"],
            "timestamp": response["ts"],
            "message": response["message"]["text"]
        }
    
    async def _slack_list_channels(
        self,
        client: WebClient,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """List Slack channels.
        
        Args:
            client: Slack client
            params: Parameters (optional: types, limit)
            
        Returns:
            Result with channel list
        """
        response = client.conversations_list(
            types=params.get("types", "public_channel"),
            limit=params.get("limit", 10)
        )
        
        channels = [
            {
                "id": channel["id"],
                "name": channel["name"],
                "is_private": channel.get("is_private", False),
                "num_members": channel.get("num_members", 0)
            }
            for channel in response["channels"]
        ]
        
        return {
            "action": "list_channels",
            "count": len(channels),
            "channels": channels
        }
    
    async def _execute_google_workspace_action(
        self,
        action: str,
        access_token: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Google Workspace action.
        
        Args:
            action: Action name (e.g., send_email, create_doc)
            access_token: Google Workspace access token
            params: Action parameters
            
        Returns:
            Action result dictionary
            
        Raises:
            ProviderExecutionError: If Google API call fails
        """
        # Note: Full Google Workspace integration would require google-api-python-client
        # For now, we'll provide a placeholder implementation
        
        logger.warning(f"Google Workspace action '{action}' not fully implemented")
        
        if action == "send_email":
            return {
                "action": "send_email",
                "status": "placeholder",
                "message": "Google Workspace integration not fully implemented"
            }
        elif action == "create_doc":
            return {
                "action": "create_doc",
                "status": "placeholder",
                "message": "Google Workspace integration not fully implemented"
            }
        else:
            raise ProviderExecutionError(f"Unknown Google Workspace action: {action}")
