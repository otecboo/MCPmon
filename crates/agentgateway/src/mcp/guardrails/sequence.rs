//! Declarative sequence rules over the recorded `tools/call` chain.
//!
//! [`crate::mcp::history`] records the calls that came before the current request and
//! exposes them to CEL as `mcp.history`. That is flexible but moves the whole rule
//! language into every policy expression. This module provides the same three rule
//! shapes the anomaly model is defined on — a banned tool, a banned pair, and a banned
//! pattern — as first-class configuration, evaluated in Rust against the same snapshot:
//!
//! * [`SequenceRule::DenyTool`] — the tool may never be called;
//! * [`SequenceRule::DenyAfter`] — `after` is denied once `before` appears earlier in
//!   the chain (order-only, not necessarily adjacent);
//! * [`SequenceRule::DenyPattern`] — the call is denied when the chain *ends* with
//!   `sequence`, i.e. the current call completes the pattern.
//!
//! Matching the tail (rather than anywhere) keeps detection tied to the step that
//! completes the violation: an earlier occurrence would already have been denied, so
//! the detection step is exactly the first completing step. That property is what makes
//! step-level metrics (detection step vs. divergence step) meaningful.
//!
//! Rules are data, not code: they are validated at config load and evaluated without
//! allocating a CEL context. With the default 64-entry history a check is a bounded
//! linear scan, so the cost does not grow with session length.
//!
//! `action: flag` reports a match through `mcpGuardrails.anomaly` (visible to access-log
//! CEL) and lets the call through; `action: reject` (the default) denies it.

use std::sync::Arc;

use rmcp::model::ErrorData;
use serde_json::json;

use crate::mcp::MCPInfo;
use crate::mcp::guardrails::McpGuardrailsDynamicMetadata;
use crate::mcp::guardrails::client::PERMISSION_DENIED;
use crate::mcp::history::{CallHistorySnapshot, CallRecord};
use crate::mcp::upstream::IncomingRequestContext;
use crate::{apply, schema, schema_enum};

/// Ordered rules plus the action taken when one matches.
#[apply(schema!)]
#[derive(Default)]
pub struct SequenceProcessor {
	/// Rules are tried in order; the first match decides. An empty list is rejected at
	/// config-load time by `load_warnings`.
	#[serde(default)]
	pub rules: Vec<SequenceRule>,
	/// What to do on a match. Defaults to `reject`.
	#[serde(default)]
	pub action: SequenceAction,
}

/// One sequence rule. Externally tagged, so the YAML is `denyTool: name`,
/// `denyAfter: {before: a, after: b}`, `denyPattern: [a, b, c]`.
#[apply(schema!)]
pub enum SequenceRule {
	/// The agent may never call this tool.
	DenyTool(String),
	/// Deny `after` once `before` was called earlier in the same session.
	DenyAfter { before: String, after: String },
	/// Deny the call that makes the chain end with this sequence.
	DenyPattern(Vec<String>),
}

#[apply(schema_enum!)]
#[derive(Default)]
pub enum SequenceAction {
	/// Reject the call with a JSON-RPC permission error.
	#[default]
	Reject,
	/// Record the match in `mcpGuardrails.anomaly` and allow the call.
	Flag,
}

impl SequenceRule {
	/// Human-readable form used in rejection messages, flag metadata and logs.
	pub fn describe(&self) -> String {
		match self {
			SequenceRule::DenyTool(tool) => format!("denyTool({tool})"),
			SequenceRule::DenyAfter { before, after } => {
				format!("denyAfter({before} -> {after})")
			},
			SequenceRule::DenyPattern(sequence) => {
				format!("denyPattern({})", sequence.join(" -> "))
			},
		}
	}

	/// Whether this rule matches the call `tool` given the chain recorded before it.
	pub fn matches(&self, tool: &str, history: &[CallRecord]) -> bool {
		match self {
			SequenceRule::DenyTool(banned) => banned.as_str() == tool,
			SequenceRule::DenyAfter { before, after } => {
				after.as_str() == tool
					&& history
						.iter()
						.any(|record| &*record.tool == before.as_str())
			},
			SequenceRule::DenyPattern(sequence) => {
				!sequence.is_empty() && chain_ends_with(history, tool, sequence)
			},
		}
	}
}

/// Whether `history ++ [tool]` ends with `sequence`.
fn chain_ends_with(history: &[CallRecord], tool: &str, sequence: &[String]) -> bool {
	let chain_len = history.len() + 1;
	if sequence.len() > chain_len {
		return false;
	}
	let offset = chain_len - sequence.len();
	for (index, expected) in sequence.iter().enumerate() {
		let position = offset + index;
		let actual = if position < history.len() {
			&*history[position].tool
		} else {
			tool
		};
		if actual != expected.as_str() {
			return false;
		}
	}
	true
}

/// Evaluates the rules for this call.
///
/// Returns `Some(error)` when the call must be rejected, `None` when it may proceed
/// (including the `flag` case, which records metadata on `req_ctx` internally).
///
/// The check is skipped when the request carries no tool information or no history
/// snapshot: a request that bypassed the MCP router has no recorded chain, and guessing
/// one would silently change policy semantics.
pub fn check(
	processor: &SequenceProcessor,
	method: &str,
	tool: Option<&str>,
	req_ctx: &mut IncomingRequestContext,
) -> Option<ErrorData> {
	if method != "tools/call" {
		return None;
	}
	// The call site passes the tool name from the request params. The `MCPInfo`
	// extension is only populated when some CEL expression needs MCP attributes, so a
	// config with sequence rules and no CEL expressions has no `MCPInfo` at all.
	let tool = tool.map(str::to_owned).or_else(|| {
		req_ctx
			.extensions()
			.get::<MCPInfo>()
			.and_then(|info| info.tool.as_ref())
			.map(|info| info.name.clone())
	});
	let Some(tool) = tool else {
		tracing::debug!(
			method,
			"mcpGuardrails: sequence rules skipped, tool name is not available"
		);
		return None;
	};
	let tool = tool.as_str();
	let Some(history) = req_ctx
		.extensions()
		.get::<Arc<CallHistorySnapshot>>()
		.cloned()
	else {
		tracing::debug!(
			tool,
			"mcpGuardrails: sequence rules skipped, no call history on this request"
		);
		return None;
	};

	let matched = processor
		.rules
		.iter()
		.find(|rule| rule.matches(tool, &history.entries));
	let Some(rule) = matched else {
		return None;
	};
	let step = history.entries.len() + 1;
	match processor.action {
		SequenceAction::Reject => Some(ErrorData::new(
			PERMISSION_DENIED,
			format!("sequence policy denied: {}", rule.describe()),
			None,
		)),
		SequenceAction::Flag => {
			tracing::warn!(
				tool,
				rule = %rule.describe(),
				step,
				"mcpGuardrails: sequence rule flagged a call"
			);
			let payload = json!({
				"rule": rule.describe(),
				"tool": tool,
				"step": step,
				"historyLength": step - 1,
			});
			record_flag(req_ctx, payload);
			None
		},
	}
}

/// Publishes a flag through `mcpGuardrails.anomaly`, the same channel remote processors
/// use for their metadata, so access-log CEL and downstream filters can see it.
fn record_flag(req_ctx: &mut IncomingRequestContext, payload: serde_json::Value) {
	let mut metadata = req_ctx
		.extensions()
		.get::<McpGuardrailsDynamicMetadata>()
		.cloned()
		.unwrap_or_default();
	metadata.0.insert("anomaly".to_string(), payload);
	// The access-log snapshot is taken before guardrails run, so update the log copy too.
	if let Some(log) = req_ctx
		.extensions()
		.get::<crate::telemetry::log::McpGuardrailsLog>()
	{
		log.store(Some(metadata.clone()));
	}
	req_ctx.extensions_mut().insert(metadata);
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mcp::history::CallRecord;

	fn record(tool: &str) -> CallRecord {
		CallRecord::new("mcp", tool)
	}

	fn chain(tools: &[&str]) -> Vec<CallRecord> {
		tools.iter().map(|tool| record(tool)).collect()
	}

	#[test]
	fn deny_tool_matches_only_that_tool() {
		let rule = SequenceRule::DenyTool("shell_exec".into());
		assert!(rule.matches("shell_exec", &[]));
		assert!(!rule.matches("echo", &chain(&["shell_exec"])));
	}

	#[test]
	fn deny_after_matches_any_earlier_occurrence() {
		let rule = SequenceRule::DenyAfter {
			before: "fs.read".into(),
			after: "http.post".into(),
		};
		assert!(rule.matches("http.post", &chain(&["fs.read"])));
		assert!(rule.matches("http.post", &chain(&["a", "fs.read", "b"])));
		assert!(!rule.matches("http.post", &chain(&["fs.write"])));
		assert!(!rule.matches("http.get", &chain(&["fs.read"])));
	}

	#[test]
	fn deny_pattern_matches_the_chain_tail() {
		let rule = SequenceRule::DenyPattern(vec![
			"fs.read".into(),
			"archive.create".into(),
			"http.post".into(),
		]);
		assert!(rule.matches("http.post", &chain(&["fs.read", "archive.create"])));
		assert!(rule.matches("http.post", &chain(&["noise", "fs.read", "archive.create"])));
		// The pattern must be contiguous and end at the current call.
		assert!(!rule.matches("http.post", &chain(&["fs.read", "noise", "archive.create"])));
		assert!(!rule.matches("archive.create", &chain(&["fs.read"])));
	}

	#[test]
	fn deny_pattern_longer_than_the_chain_cannot_match() {
		let rule = SequenceRule::DenyPattern(vec!["a".into(), "b".into(), "c".into()]);
		assert!(!rule.matches("c", &[]));
		assert!(!rule.matches("b", &chain(&["a"])));
	}

	#[test]
	fn deny_pattern_of_one_is_a_tool_ban() {
		let rule = SequenceRule::DenyPattern(vec!["echo".into()]);
		assert!(rule.matches("echo", &[]));
		assert!(!rule.matches("increment", &[]));
	}

	#[test]
	fn describe_renders_the_rule() {
		assert_eq!(
			SequenceRule::DenyAfter {
				before: "a".into(),
				after: "b".into()
			}
			.describe(),
			"denyAfter(a -> b)"
		);
		assert_eq!(
			SequenceRule::DenyPattern(vec!["a".into(), "b".into()]).describe(),
			"denyPattern(a -> b)"
		);
	}

	#[test]
	fn check_ignores_other_methods_and_missing_tool() {
		let processor = SequenceProcessor {
			rules: vec![SequenceRule::DenyTool("echo".into())],
			action: SequenceAction::Reject,
		};
		let (parts, _) = ::http::Request::new(()).into_parts();
		let mut ctx = IncomingRequestContext::new(&parts);
		assert!(check(&processor, "tools/list", Some("echo"), &mut ctx).is_none());
		assert!(check(&processor, "tools/call", None, &mut ctx).is_none());
	}

	fn context_with_history(tools: &[&str]) -> IncomingRequestContext {
		let (parts, _) = ::http::Request::new(()).into_parts();
		let mut ctx = IncomingRequestContext::new(&parts);
		let entries = tools
			.iter()
			.map(|tool| CallRecord::new("mcp", *tool))
			.collect();
		ctx
			.extensions_mut()
			.insert(Arc::new(CallHistorySnapshot { entries }));
		ctx
	}

	#[test]
	fn check_denies_the_call_that_completes_a_pattern() {
		let processor = SequenceProcessor {
			rules: vec![SequenceRule::DenyPattern(vec![
				"increment".into(),
				"decrement".into(),
				"echo".into(),
			])],
			action: SequenceAction::Reject,
		};
		let mut ctx = context_with_history(&["increment", "decrement"]);
		let error = check(&processor, "tools/call", Some("echo"), &mut ctx)
			.expect("the completing call must be denied");
		assert!(
			error
				.message
				.contains("denyPattern(increment -> decrement -> echo)"),
			"unexpected message: {error:?}"
		);
	}

	#[test]
	fn flag_records_metadata_and_allows_the_call() {
		let processor = SequenceProcessor {
			rules: vec![SequenceRule::DenyAfter {
				before: "increment".into(),
				after: "echo".into(),
			}],
			action: SequenceAction::Flag,
		};
		let mut ctx = context_with_history(&["increment"]);
		assert!(check(&processor, "tools/call", Some("echo"), &mut ctx).is_none());
		let metadata = ctx
			.extensions()
			.get::<McpGuardrailsDynamicMetadata>()
			.expect("flag metadata is recorded");
		let anomaly = metadata.0.get("anomaly").expect("anomaly entry");
		assert_eq!(anomaly["rule"], "denyAfter(increment -> echo)");
	}
}
