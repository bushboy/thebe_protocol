# Requirements Document

## Introduction

This document specifies the requirements for the Guardian Agent UI, a standalone application that provides a conversational chat interface for interacting with the Zero-Trust Agentic Guardian services. The application consists of a JavaScript frontend (chat UI) that communicates with a Python agent API layer (FastAPI with LangChain or Agno), which in turn orchestrates calls to the Guardian microservices. The application is fully portable and has zero coupling to the Guardian codebase — it communicates exclusively through the Guardian's HTTP API contracts.

## Glossary

- **Chat_UI**: The JavaScript frontend application that renders a conversational interface for users to submit goals and view execution results.
- **Agent_API**: The Python FastAPI backend that receives user messages from the Chat_UI, uses an LLM orchestration framework (LangChain or Agno) to reason about user goals, and calls Guardian services.
- **Guardian_Services**: The existing set of Zero-Trust Agentic Guardian microservices (Planner, Intent Engine, Safety Agent, Permission Broker, Executor, Audit) that implement the zero-trust authorization chain.
- **Guardian_Client**: A self-contained HTTP client module within the Agent_API that handles all communication with Guardian_Services, including triple authentication (mTLS + JWT + DPoP).
- **Plan**: A task execution plan returned by the Guardian Planner service, containing a plan_id, task_graph, and intent_signature.
- **Task_Graph**: An ordered list of tasks with dependencies, where each task specifies a task_id, action, provider, and dependency list.
- **Intent_Signature**: A cryptographic signature containing semantic embeddings, allowed actions, and a hash of the user goal, produced by the Guardian Intent Engine.
- **Triple_Authentication**: The Guardian's service-to-service authentication mechanism combining mTLS (mutual TLS), JWT (JSON Web Tokens), and DPoP (Demonstrating Proof-of-Possession).
- **Agent_Session**: A stateful conversation context maintained by the Agent_API for a single user, tracking message history, active plans, and execution state.
- **Execution_Result**: The outcome of executing a task through the Guardian authorization chain, including status, result data, and any error information.
- **Testing_Mode**: A configurable operational mode of the application that enables security testing features, pre-built attack scenarios, and detailed Guardian decision visibility.
- **Attack_Scenario**: A pre-defined test case consisting of a prompt injection payload or a destructive agent action, along with the expected Guardian response (block, flag, or allow).
- **Security_Decision**: A structured record of a Guardian security evaluation, including the decision outcome (approved or blocked), the reason category (intent misalignment, policy violation, or authentication failure), and supporting details such as similarity scores and policy rule identifiers.
- **Intent_Misalignment_Score**: A numeric similarity score (0.0 to 1.0) produced by the Intent Engine that measures how closely a proposed action aligns with the original user goal; scores below the configured threshold (default 0.7) indicate misalignment.
- **Prompt_Injection_Attempt**: A user-submitted message that intentionally contains adversarial instructions designed to manipulate the LLM or bypass Guardian security controls.

## Requirements

### Requirement 1: Chat UI Message Submission

**User Story:** As a user, I want to type goals and messages into a chat interface, so that I can interact with the Guardian agent conversationally.

#### Acceptance Criteria

1. THE Chat_UI SHALL render a text input field and a send button for composing messages.
2. WHEN the user submits a message, THE Chat_UI SHALL send the message text to the Agent_API via an HTTP POST request to the `/chat` endpoint.
3. WHEN the user submits a message, THE Chat_UI SHALL display the user message in the conversation thread immediately before receiving a response.
4. WHILE the Agent_API is processing a request, THE Chat_UI SHALL display a loading indicator in the conversation thread.
5. WHEN the Agent_API returns a response, THE Chat_UI SHALL display the agent response in the conversation thread.
6. IF the Agent_API returns an error response, THEN THE Chat_UI SHALL display a user-readable error message in the conversation thread.

### Requirement 2: Chat UI Conversation Display

**User Story:** As a user, I want to see a scrollable history of my conversation with the agent, so that I can review past interactions and understand the context.

#### Acceptance Criteria

1. THE Chat_UI SHALL display messages in chronological order within a scrollable container.
2. THE Chat_UI SHALL visually distinguish user messages from agent messages using different alignment or styling.
3. WHEN a new message is added to the conversation, THE Chat_UI SHALL auto-scroll to the most recent message.
4. THE Chat_UI SHALL display a timestamp for each message.

### Requirement 3: Chat UI Plan Visualization

**User Story:** As a user, I want to see the task execution plan generated from my goal, so that I can understand what actions the agent will perform before they execute.

#### Acceptance Criteria

1. WHEN the Agent_API returns a plan response, THE Chat_UI SHALL render the task graph as a structured list showing each task's action, provider, and dependencies.
2. THE Chat_UI SHALL display the plan_id associated with each plan.
3. WHEN a task in the plan has dependencies, THE Chat_UI SHALL visually indicate the dependency relationship.
4. THE Chat_UI SHALL display the plan status (pending approval, executing, completed, or failed) for each plan.

### Requirement 4: Chat UI Plan Approval Flow

**User Story:** As a user, I want to approve or reject a proposed plan before execution begins, so that I maintain control over what actions the agent performs.

#### Acceptance Criteria

1. WHEN a plan is presented to the user, THE Chat_UI SHALL display an "Approve" button and a "Reject" button alongside the plan.
2. WHEN the user clicks the "Approve" button, THE Chat_UI SHALL send an approval request to the Agent_API via an HTTP POST request to the `/chat/{session_id}/approve` endpoint.
3. WHEN the user clicks the "Reject" button, THE Chat_UI SHALL send a rejection request to the Agent_API and display a confirmation that the plan was rejected.
4. WHILE a plan is awaiting user approval, THE Chat_UI SHALL prevent submission of new goals.

### Requirement 5: Chat UI Execution Progress

**User Story:** As a user, I want to see real-time progress as the agent executes tasks in my approved plan, so that I know what is happening.

#### Acceptance Criteria

1. WHILE a plan is executing, THE Chat_UI SHALL poll the Agent_API `/chat/{session_id}/status` endpoint at a configurable interval (default 2 seconds) for execution updates.
2. WHEN a task execution status changes, THE Chat_UI SHALL update the task's visual status indicator (pending, running, succeeded, or failed).
3. WHEN all tasks in a plan complete successfully, THE Chat_UI SHALL display a summary of execution results.
4. IF a task execution fails, THEN THE Chat_UI SHALL display the error details for the failed task and halt progress display for dependent tasks.

### Requirement 6: Agent API Chat Endpoint

**User Story:** As a frontend developer, I want a single chat endpoint that accepts user messages and returns agent responses, so that the frontend has a simple integration point.

#### Acceptance Criteria

1. THE Agent_API SHALL expose a `POST /chat` endpoint that accepts a JSON body containing `message` (string), `session_id` (string, optional), and `context` (object, optional with fields `role` and `allowed_providers`).
2. WHEN a request is received without a `session_id`, THE Agent_API SHALL create a new Agent_Session and return the generated `session_id` in the response.
3. WHEN a request is received with a valid `session_id`, THE Agent_API SHALL load the existing Agent_Session and include conversation history in the LLM context.
4. THE Agent_API SHALL return a JSON response containing `session_id` (string), `message` (string), `plan` (object, nullable), and `requires_approval` (boolean).
5. IF a request is received with an invalid or expired `session_id`, THEN THE Agent_API SHALL return an HTTP 404 response with an error message.

### Requirement 7: Agent API LLM Orchestration

**User Story:** As a system architect, I want the agent layer to use LangChain or Agno to reason about user goals and decide when to call Guardian services, so that the agent can handle conversational context and multi-step workflows.

#### Acceptance Criteria

1. THE Agent_API SHALL use LangChain or Agno as the LLM orchestration framework for processing user messages.
2. WHEN the LLM determines that a user message contains an actionable goal, THE Agent_API SHALL call the Guardian_Client to submit the goal to the Guardian `/plan` endpoint.
3. WHEN the LLM determines that a user message is conversational (not an actionable goal), THE Agent_API SHALL respond with a conversational reply without calling Guardian_Services.
4. THE Agent_API SHALL include the Agent_Session conversation history as context for each LLM invocation.
5. THE Agent_API SHALL define the Guardian plan submission as a tool/function that the LLM can invoke.

### Requirement 8: Guardian Client — Plan Submission

**User Story:** As a backend developer, I want a self-contained Guardian client module that handles plan submission with proper authentication, so that the Agent_API can communicate with Guardian services without coupling to their codebase.

#### Acceptance Criteria

1. THE Guardian_Client SHALL send HTTP POST requests to the Guardian `/plan` endpoint with a JSON body containing `user_goal` (string), `user_id` (string), and `context` (object with `role` and `allowed_providers` fields).
2. WHEN the Guardian `/plan` endpoint returns a successful response, THE Guardian_Client SHALL parse the response into a Plan object containing `plan_id`, `task_graph`, and `intent_signature`.
3. IF the Guardian `/plan` endpoint returns an HTTP error response, THEN THE Guardian_Client SHALL raise a typed exception containing the HTTP status code and error details.
4. THE Guardian_Client SHALL authenticate all requests using Triple_Authentication (mTLS + JWT + DPoP).
5. THE Guardian_Client SHALL read Guardian service URLs and authentication credentials from environment variables or a configuration file.
6. FOR ALL valid Plan objects, serializing a Plan to JSON then deserializing back to a Plan SHALL produce an equivalent object (round-trip property).

### Requirement 9: Guardian Client — Triple Authentication

**User Story:** As a security engineer, I want the Guardian client to implement the full triple authentication stack, so that the standalone application can securely communicate with Guardian services.

#### Acceptance Criteria

1. THE Guardian_Client SHALL attach a client TLS certificate and key for mTLS on every request to Guardian_Services.
2. THE Guardian_Client SHALL obtain a JWT access token and include it in the `Authorization` header as a Bearer token on every request to Guardian_Services.
3. THE Guardian_Client SHALL generate a DPoP proof bound to the HTTP method and URL of each request and include it in the `DPoP` header.
4. THE Guardian_Client SHALL read the mTLS certificate path, key path, and CA certificate path from configuration.
5. WHEN a JWT access token expires, THE Guardian_Client SHALL obtain a new token before retrying the request.
6. THE Guardian_Client SHALL validate that the DPoP proof `iat` timestamp is within the configured freshness window (default 60 seconds).

### Requirement 10: Agent API Plan Approval and Execution

**User Story:** As a user, I want the agent to wait for my approval before executing a plan and then orchestrate execution through the Guardian services, so that I have control and visibility over the process.

#### Acceptance Criteria

1. WHEN the Guardian_Client returns a Plan, THE Agent_API SHALL store the Plan in the Agent_Session and return a response with `requires_approval` set to `true`.
2. THE Agent_API SHALL expose a `POST /chat/{session_id}/approve` endpoint that accepts a JSON body containing `plan_id` (string) and `approved` (boolean).
3. WHEN the user approves a plan, THE Agent_API SHALL initiate execution of the task graph by calling Guardian_Services for each task in dependency order.
4. WHEN the user rejects a plan, THE Agent_API SHALL mark the plan as rejected in the Agent_Session and return a confirmation response.
5. IF the user attempts to approve a plan that does not exist in the session, THEN THE Agent_API SHALL return an HTTP 404 response.

### Requirement 11: Agent API Execution Status

**User Story:** As a frontend developer, I want a status endpoint that returns the current execution state of a plan, so that the Chat_UI can poll for progress updates.

#### Acceptance Criteria

1. THE Agent_API SHALL expose a `GET /chat/{session_id}/status` endpoint that returns the current execution state.
2. THE Agent_API SHALL return a JSON response containing `session_id`, `plan_id`, `status` (one of: idle, awaiting_approval, executing, completed, failed), and `tasks` (array of task status objects with `task_id`, `status`, `result`, and `error` fields).
3. WHEN a task completes execution, THE Agent_API SHALL update the task status in the Agent_Session to "succeeded" or "failed" with the corresponding result or error.
4. IF the `session_id` does not exist, THEN THE Agent_API SHALL return an HTTP 404 response.

### Requirement 12: Agent API Session Management

**User Story:** As a system architect, I want sessions to be managed with proper lifecycle controls, so that resources are cleaned up and stale sessions do not accumulate.

#### Acceptance Criteria

1. THE Agent_API SHALL assign a unique identifier (UUID) to each new Agent_Session.
2. THE Agent_API SHALL store Agent_Session data in an in-memory store with a configurable time-to-live (default 30 minutes of inactivity).
3. WHEN an Agent_Session exceeds the time-to-live without activity, THE Agent_API SHALL remove the session data from the store.
4. WHEN a request is received for an active session, THE Agent_API SHALL reset the session's inactivity timer.

### Requirement 13: Agent API Configuration

**User Story:** As a DevOps engineer, I want all external service URLs and credentials to be configurable via environment variables, so that the application can be deployed in any environment without code changes.

#### Acceptance Criteria

1. THE Agent_API SHALL read the Guardian Planner service URL from the `GUARDIAN_PLANNER_URL` environment variable.
2. THE Agent_API SHALL read the LLM provider API key from the `LLM_API_KEY` environment variable.
3. THE Agent_API SHALL read mTLS certificate paths from `MTLS_CERT_PATH`, `MTLS_KEY_PATH`, and `MTLS_CA_CERT_PATH` environment variables.
4. THE Agent_API SHALL read JWT authentication credentials from `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` environment variables.
5. IF a required environment variable is missing at startup, THEN THE Agent_API SHALL exit with a non-zero exit code and log a message identifying the missing variable.

### Requirement 14: Agent API Error Handling

**User Story:** As a developer, I want consistent and informative error responses from the Agent API, so that the frontend can display meaningful feedback to users.

#### Acceptance Criteria

1. THE Agent_API SHALL return all error responses in a consistent JSON format containing `error` (string error code) and `message` (string description).
2. IF the Guardian_Services are unreachable, THEN THE Agent_API SHALL return an HTTP 502 response with error code `guardian_unavailable`.
3. IF the LLM provider is unreachable, THEN THE Agent_API SHALL return an HTTP 502 response with error code `llm_unavailable`.
4. IF a request body fails validation, THEN THE Agent_API SHALL return an HTTP 422 response with error code `validation_error` and a description of the invalid fields.
5. THE Agent_API SHALL log all errors with structured JSON logging including a correlation ID, timestamp, error type, and stack trace.

### Requirement 15: Agent API Health Check

**User Story:** As a DevOps engineer, I want a health check endpoint, so that I can monitor the application's availability and downstream connectivity.

#### Acceptance Criteria

1. THE Agent_API SHALL expose a `GET /health` endpoint that returns the service health status.
2. THE Agent_API SHALL return a JSON response containing `status` (one of: healthy, degraded, unhealthy), `version` (string), and `dependencies` (object with connectivity status for Guardian_Services and the LLM provider).
3. WHEN all dependencies are reachable, THE Agent_API SHALL return `status` as "healthy".
4. WHEN one or more dependencies are unreachable, THE Agent_API SHALL return `status` as "degraded" and identify the unreachable dependencies.

### Requirement 16: Application Portability

**User Story:** As a system architect, I want the application to be fully self-contained and portable, so that it can be deployed independently of the Guardian codebase and pointed at any compatible Guardian deployment.

#### Acceptance Criteria

1. THE Agent_API SHALL have zero import dependencies on the Guardian codebase.
2. THE Agent_API SHALL define its own Pydantic models for all Guardian API request and response schemas.
3. THE Guardian_Client SHALL communicate with Guardian_Services exclusively through HTTP API calls.
4. THE Chat_UI SHALL be a standalone JavaScript application that communicates with the Agent_API exclusively through HTTP API calls.
5. THE application SHALL include a `docker-compose.yml` file that starts both the Chat_UI and Agent_API as separate containers.

### Requirement 17: Guardian API Schema Serialization

**User Story:** As a developer, I want the Guardian API schemas to be correctly serializable and deserializable, so that data integrity is maintained across the network boundary.

#### Acceptance Criteria

1. THE Agent_API SHALL define Pydantic models for `PlanRequest`, `PlanResponse`, `TaskGraphItem`, and `IntentSignature` that match the Guardian API contract.
2. FOR ALL valid PlanRequest objects, serializing to JSON then deserializing back to a PlanRequest SHALL produce an equivalent object (round-trip property).
3. FOR ALL valid PlanResponse objects, serializing to JSON then deserializing back to a PlanResponse SHALL produce an equivalent object (round-trip property).
4. FOR ALL valid IntentSignature objects, serializing to JSON then deserializing back to an IntentSignature SHALL produce an equivalent object (round-trip property).

### Requirement 18: Prompt Injection Testing

**User Story:** As a security engineer, I want to submit prompt injection attempts through the Chat_UI and observe how the Guardian detects and blocks them, so that I can validate the Guardian's prompt injection defenses.

#### Acceptance Criteria

1. WHILE Testing_Mode is enabled, THE Chat_UI SHALL display a "Prompt Injection Test" panel that lists pre-built Prompt_Injection_Attempt payloads organized by category (goal hijacking, instruction override, context manipulation, and data exfiltration).
2. WHEN the user selects a pre-built Prompt_Injection_Attempt, THE Chat_UI SHALL populate the message input with the selected payload and allow the user to edit it before submission.
3. WHEN a Prompt_Injection_Attempt is submitted, THE Agent_API SHALL forward the message through the full Guardian authorization chain (Planner, Intent Engine, Safety Agent) without bypassing any security checks.
4. WHEN the Guardian Intent Engine returns an Intent_Misalignment_Score below the configured threshold for a submitted message, THE Chat_UI SHALL display the rejection with the label "Prompt Injection Detected" and show the Intent_Misalignment_Score.
5. WHILE Testing_Mode is enabled, THE Chat_UI SHALL allow users to compose and submit custom Prompt_Injection_Attempt payloads through the standard message input.
6. WHEN a Prompt_Injection_Attempt is processed, THE Agent_API SHALL return the complete Security_Decision in the response, including the Intent_Misalignment_Score, the original intent embedding hash, and the misaligned action list.

### Requirement 19: Destructive Action Testing

**User Story:** As a security engineer, I want to test scenarios where the agent proposes harmful or destructive actions, so that I can verify the Guardian's Safety Agent and policy enforcement catch dangerous operations.

#### Acceptance Criteria

1. WHILE Testing_Mode is enabled, THE Chat_UI SHALL display a "Destructive Action Scenarios" panel that lists pre-built Attack_Scenarios involving dangerous operations (mass file deletion, unauthorized privilege escalation, credential exfiltration, and unrestricted API calls).
2. WHEN the user selects a destructive Attack_Scenario, THE Agent_API SHALL submit the scenario goal to the Guardian Planner and forward the resulting plan through the Safety Agent for policy evaluation.
3. WHEN the Guardian Safety Agent rejects a task due to a policy violation, THE Agent_API SHALL return the Security_Decision containing the violated policy rule identifier, the policy category, and the rejection reason.
4. WHEN the Guardian Safety Agent rejects a task, THE Chat_UI SHALL display the rejected task with a "Blocked by Policy" label, the violated policy rule identifier, and the human-readable rejection reason.
5. WHILE Testing_Mode is enabled, THE Chat_UI SHALL allow users to define custom destructive goals through the standard message input and observe the Guardian's policy enforcement response.
6. WHEN a destructive Attack_Scenario results in the Guardian Permission Broker denying the Zero-Trust Authorization Token, THE Agent_API SHALL return the denial reason including which authorization chain link failed (mTLS, JWT, DPoP, or policy).

### Requirement 20: Testing and Demo Mode

**User Story:** As a developer or security auditor, I want a dedicated testing mode that provides pre-built attack scenarios and detailed visibility into Guardian security decisions, so that I can systematically exercise and validate the Guardian's security capabilities.

#### Acceptance Criteria

1. THE Agent_API SHALL accept a `TESTING_MODE` environment variable (values: "enabled" or "disabled", default "disabled") that activates Testing_Mode.
2. WHEN Testing_Mode is enabled, THE Agent_API SHALL expose a `GET /testing/scenarios` endpoint that returns the list of pre-built Attack_Scenarios grouped by category (prompt_injection, destructive_action, policy_violation, and authentication_bypass).
3. WHEN Testing_Mode is enabled, THE Agent_API SHALL expose a `GET /testing/decisions` endpoint that returns a paginated list of all Security_Decisions recorded during the current session, ordered by timestamp descending.
4. WHEN Testing_Mode is enabled, THE Agent_API SHALL expose a `GET /testing/decisions/{decision_id}` endpoint that returns the full Security_Decision detail including the intent signature verification result, the policy evaluation trace, and the authorization chain validation result.
5. WHEN Testing_Mode is enabled, THE Chat_UI SHALL display a "Security Dashboard" sidebar showing a running count of total tests executed, tests blocked, tests allowed, and the block rate as a percentage.
6. WHEN Testing_Mode is enabled, THE Chat_UI SHALL display a "Decision Log" panel that lists each Security_Decision with its timestamp, decision outcome, reason category, and a link to the full detail view.
7. WHILE Testing_Mode is disabled, THE Agent_API SHALL return an HTTP 404 response for all `/testing/*` endpoints.
8. THE Agent_API SHALL include an `X-Testing-Mode` response header with value "enabled" or "disabled" on all responses, so that the Chat_UI can detect the current mode.
9. WHEN Testing_Mode is enabled, THE Chat_UI SHALL display a visible "Testing Mode" banner at the top of the interface to indicate that testing features are active.

### Requirement 21: Security Decision Transparency

**User Story:** As a user, I want to see detailed explanations of why the Guardian blocked or approved an action, so that I can understand the security reasoning and trust the system's decisions.

#### Acceptance Criteria

1. WHEN the Guardian blocks an action, THE Chat_UI SHALL display a Security_Decision card in the conversation thread containing the decision outcome, the reason category, and a human-readable explanation.
2. WHEN a Security_Decision includes an Intent_Misalignment_Score, THE Chat_UI SHALL display the score as a numeric value and a visual indicator (color-coded bar: green for scores above 0.8, yellow for scores between 0.7 and 0.8, red for scores below 0.7).
3. WHEN a Security_Decision includes a policy violation, THE Chat_UI SHALL display the policy rule identifier, the policy category, and the specific condition that was violated.
4. WHEN a Security_Decision includes an authorization chain failure, THE Chat_UI SHALL identify which link in the chain failed (mTLS certificate validation, JWT token validation, or DPoP proof validation) and display the failure reason.
5. THE Agent_API SHALL include a `security_decisions` array in the response for every `/chat` request that triggered Guardian evaluation, where each entry contains `decision_id` (string), `outcome` (one of: approved, blocked), `reason_category` (one of: intent_misalignment, policy_violation, auth_failure, approved), `details` (object), and `timestamp` (ISO 8601 string).
6. WHEN the Guardian approves an action, THE Chat_UI SHALL display a compact approval indicator showing the Intent_Misalignment_Score and a "Verified" label.
7. WHEN the user clicks on a Security_Decision card, THE Chat_UI SHALL expand the card to show the full decision detail including the raw intent signature verification result and the complete policy evaluation trace.
