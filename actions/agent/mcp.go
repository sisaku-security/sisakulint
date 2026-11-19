package agent

// githubMCPWrites are the tools of github-mcp-server v0.17.1 that write,
// which claude-code-action runs with every toolset and the step's token:
// each takes its target (the owner and the repository, a gist, a thread)
// as an argument
// (https://github.com/github/github-mcp-server/blob/23fa0dd1a821d1346c1de2abafe7327d26981606/pkg/github/tools.go,
// AddWriteTools). The tools that read give no capability.
var githubMCPWrites = []string{
	// repos
	"create_or_update_file", "create_repository", "fork_repository", "create_branch", "push_files", "delete_file", "star_repository", "unstar_repository",
	// issues
	"create_issue", "add_issue_comment", "update_issue", "assign_copilot_to_issue", "add_sub_issue", "remove_sub_issue", "reprioritize_sub_issue",
	// pull_requests
	"merge_pull_request", "update_pull_request_branch", "create_pull_request", "update_pull_request", "request_copilot_review",
	"create_and_submit_pull_request_review", "create_pending_pull_request_review", "add_comment_to_pending_review", "submit_pending_pull_request_review", "delete_pending_pull_request_review",
	// actions
	"run_workflow", "rerun_workflow_run", "rerun_failed_jobs", "cancel_workflow_run", "delete_workflow_run_logs",
	// notifications
	"dismiss_notification", "mark_all_notifications_read", "manage_notification_subscription", "manage_repository_notification_subscription",
	// gists
	"create_gist", "update_gist",
	// projects
	"add_project_item", "delete_project_item",
}

// actionServers are the MCP servers claude-code-action runs itself
// (as read on 2026-10-11): but github-mcp-server, their tools write
// only to targets the action fixes (its comment, its branch, its pull
// request).
var actionServers = []string{"github", "github_comment", "github_file_ops", "github_inline_comment", "github_ci"}
