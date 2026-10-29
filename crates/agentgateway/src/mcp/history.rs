//! Bounded, principal-scoped history of MCP `tools/call` invocations.
//!
//! MCP policies in agentgateway are evaluated per request: a guardrail sees the
//! current call and its params, but nothing about the calls that preceded it, so
//! sequence-level policies ("no `http.post` after `fs.read`") cannot be expressed.
//! This module records a small ring buffer of recent calls per principal and hands
//! it to the CEL evaluator as `mcp.history`, letting a policy reason over the chain
//! instead of a single message.
//!
//! # Scope
//!
//! Only `tools/call` is recorded. `resources/read`, prompts and tasks are not: the
//! history exists to detect anomalous tool-call sequences.
//!
//! # Identity
//!
//! `mcp-session-id` is a legacy-protocol concept. MCP `2026-07-28`+ has no sessions
//! (SEP-2567) and the gateway also supports stateless mode, so a bucket key must not
//! depend on it. A bucket is keyed by, in order of preference:
//!
//! 1. the authenticated principal (`jwt.iss` + `jwt.sub`, or a truncated API-key digest),
//! 2. the protocol session id, when present (legacy clients without authentication),
//! 3. the literal `anonymous` (unauthenticated modern clients).
//!
//! A client may split one logical agent conversation into its own bucket by setting
//! `_meta["agentsecuregateway.dev/conversationId"]` (or the bare `conversationId` key)
//! on `tools/call`; the value is appended to the principal.
//!
//! # Bounds
//!
//! Each bucket keeps at most [`MAX_ENTRIES_PER_SESSION`] calls, the store keeps at most
//! [`MAX_SESSIONS`] buckets, and buckets idle for longer than [`SESSION_TTL`] are pruned.
//! A store therefore holds at most `MAX_ENTRIES_PER_SESSION * MAX_SESSIONS` records
//! regardless of traffic, which bounds the memory a caller can make the gateway hold.
//!
//! The current call is *not* part of the snapshot a policy sees (it is exposed as
//! `mcp.params`), and a call is recorded only after it is authorized, so rejected
//! attempts never become part of the chain.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_core::prelude::Strng;
use parking_lot::Mutex;
use rmcp::model::RequestMetaObject;
use rmcp::transport::common::http_header::HEADER_SESSION_ID;

use crate::mcp::upstream::IncomingRequestContext;
use crate::types::agent::ResourceName;
use crate::{apply, schema};

/// Maximum number of calls retained per history bucket.
pub const MAX_ENTRIES_PER_SESSION: usize = 64;
/// Maximum number of concurrent history buckets.
pub const MAX_SESSIONS: usize = 4096;
/// Idle lifetime of a history bucket.
pub const SESSION_TTL: Duration = Duration::from_mins(15);
/// `_meta` key carrying an explicit conversation id on `tools/call`.
pub const CONVERSATION_ID_META_KEY: &str = "agentsecuregateway.dev/conversationId";
/// Bare `_meta` key accepted as a convenience for clients that do not namespace keys.
const CONVERSATION_ID_META_KEY_BARE: &str = "conversationId";
/// Prune expired buckets every N writes, so idle sessions do not accumulate.
const PRUNE_INTERVAL_WRITES: u64 = 256;
/// Separator that cannot appear in resource names, principals or conversation ids.
const KEY_SEPARATOR: char = '\u{1f}';
/// Length of the API-key digest kept in the identity key.
const API_KEY_DIGEST_PREFIX: usize = 16;

/// One recorded `tools/call`, exposed to CEL as an element of `mcp.history`.
#[apply(schema!)]
#[derive(PartialEq, ::cel::DynamicType)]
pub struct CallRecord {
	/// The MCP target (upstream) that served the call.
	pub target: Strng,
	/// The tool name in the target's own namespace, never multiplex-prefixed.
	pub tool: Strng,
	/// Wall-clock time of the call, in milliseconds since the Unix epoch.
	pub timestamp: i64,
}

impl CallRecord {
	pub fn new(target: impl Into<Strng>, tool: impl Into<Strng>) -> Self {
		Self {
			target: target.into(),
			tool: tool.into(),
			timestamp: now_millis(),
		}
	}
}

fn now_millis() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_millis() as i64)
		.unwrap_or_default()
}

/// The calls recorded before the current request, oldest first.
///
/// Stored in request extensions for the duration of one request and exposed to CEL
/// through [`crate::mcp::MCPView`].
#[derive(Debug, Clone, Default)]
pub struct CallHistorySnapshot {
	pub entries: Vec<CallRecord>,
}

impl CallHistorySnapshot {
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}
}

/// Opaque key identifying one history bucket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HistoryKey(String);

impl HistoryKey {
	pub fn new(backend: &str, principal: &str, conversation: Option<&str>) -> Self {
		let mut key = String::with_capacity(backend.len() + principal.len() + 8);
		key.push_str(backend);
		key.push(KEY_SEPARATOR);
		key.push_str(principal);
		key.push(KEY_SEPARATOR);
		key.push_str(conversation.unwrap_or("-"));
		Self(key)
	}

	pub fn as_str(&self) -> &str {
		&self.0
	}
}

/// Resolves the history bucket for a `tools/call` request.
///
/// `meta` is the call's JSON-RPC `_meta`, which carries the optional conversation id;
/// it is distinct from the HTTP request extensions carried by `ctx`.
pub fn scope(
	backend: &ResourceName,
	ctx: &IncomingRequestContext,
	meta: Option<&RequestMetaObject>,
) -> HistoryKey {
	let principal = principal_of(ctx);
	let conversation = conversation_id(meta);
	HistoryKey::new(&backend.to_string(), &principal, conversation.as_deref())
}

/// The authenticated principal, falling back to the protocol session and then to
/// `anonymous`. Two principals never share a bucket, and neither does one principal
/// across backends (the backend is part of the key).
fn principal_of(ctx: &IncomingRequestContext) -> String {
	let extensions = ctx.extensions();
	if let Some(claims) = extensions.get::<crate::http::jwt::Claims>()
		&& let Some(subject) = claims.inner.get("sub").and_then(|value| value.as_str())
	{
		let issuer = claims
			.inner
			.get("iss")
			.and_then(|value| value.as_str())
			.unwrap_or("-");
		return format!("jwt:{issuer}:{subject}");
	}
	if let Some(claims) = extensions.get::<crate::http::apikey::Claims>() {
		// API keys are bearer secrets: key the bucket by a digest prefix, never by the key.
		let digest = claims.key.sha256();
		let short: String = digest
			.as_str()
			.chars()
			.take(API_KEY_DIGEST_PREFIX)
			.collect();
		return format!("apikey:{short}");
	}
	if let Some(session) = session_id(ctx) {
		return format!("session:{session}");
	}
	"anonymous".to_string()
}

fn session_id(ctx: &IncomingRequestContext) -> Option<&str> {
	ctx
		.headers()
		.get(HEADER_SESSION_ID)
		.and_then(|value| value.to_str().ok())
}

fn conversation_id(meta: Option<&RequestMetaObject>) -> Option<String> {
	let map = &meta?.0.0;
	map
		.get(CONVERSATION_ID_META_KEY)
		.or_else(|| map.get(CONVERSATION_ID_META_KEY_BARE))
		.and_then(|value| value.as_str())
		.filter(|value| !value.is_empty())
		.map(str::to_owned)
}

/// Per-gateway store of tool-call histories.
///
/// One instance lives in [`crate::mcp::App`]; every MCP request receives a cheap
/// `Arc` clone in its extensions. Locking is `parking_lot` and never held across an
/// `.await`, so the store adds no scheduling to the request path.
#[derive(Debug)]
pub struct McpHistoryStore {
	inner: Mutex<Inner>,
	max_entries: usize,
	max_sessions: usize,
	ttl: Duration,
}

#[derive(Debug, Default)]
struct Inner {
	buckets: HashMap<HistoryKey, Bucket>,
	writes: u64,
}

#[derive(Debug)]
struct Bucket {
	entries: VecDeque<CallRecord>,
	last_seen: Instant,
}

impl Default for McpHistoryStore {
	fn default() -> Self {
		Self::new()
	}
}

impl McpHistoryStore {
	pub fn new() -> Self {
		Self::with_limits(MAX_ENTRIES_PER_SESSION, MAX_SESSIONS, SESSION_TTL)
	}

	/// Builds a store with explicit bounds; used by tests and by future configuration.
	pub fn with_limits(max_entries: usize, max_sessions: usize, ttl: Duration) -> Self {
		Self {
			inner: Mutex::new(Inner::default()),
			max_entries: max_entries.max(1),
			max_sessions: max_sessions.max(1),
			ttl,
		}
	}

	/// Returns the calls recorded before the current request, oldest first.
	pub fn snapshot(&self, key: &HistoryKey) -> Arc<CallHistorySnapshot> {
		let mut inner = self.inner.lock();
		let entries = match inner.buckets.get_mut(key) {
			Some(bucket) => {
				bucket.last_seen = Instant::now();
				bucket.entries.iter().cloned().collect()
			},
			None => Vec::new(),
		};
		Arc::new(CallHistorySnapshot { entries })
	}

	/// Appends an authorized call to the bucket, trimming the oldest records.
	pub fn record(&self, key: HistoryKey, record: CallRecord) {
		let mut inner = self.inner.lock();
		inner.writes = inner.writes.wrapping_add(1);
		if inner.writes % PRUNE_INTERVAL_WRITES == 0 {
			prune_expired(&mut inner.buckets, self.ttl);
		}
		if !inner.buckets.contains_key(&key) && inner.buckets.len() >= self.max_sessions {
			evict_oldest(&mut inner.buckets, self.max_sessions.saturating_sub(1));
		}
		let max_entries = self.max_entries;
		let bucket = inner.buckets.entry(key).or_insert_with(|| Bucket {
			entries: VecDeque::with_capacity(max_entries.min(8)),
			last_seen: Instant::now(),
		});
		push_bounded(&mut bucket.entries, record, max_entries);
		bucket.last_seen = Instant::now();
	}

	/// Number of retained buckets. Exposed for diagnostics and tests.
	pub fn len(&self) -> usize {
		self.inner.lock().buckets.len()
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

fn push_bounded(entries: &mut VecDeque<CallRecord>, record: CallRecord, max_entries: usize) {
	entries.push_back(record);
	while entries.len() > max_entries {
		entries.pop_front();
	}
}

fn prune_expired(buckets: &mut HashMap<HistoryKey, Bucket>, ttl: Duration) {
	let now = Instant::now();
	buckets.retain(|_, bucket| now.duration_since(bucket.last_seen) < ttl);
}

fn evict_oldest(buckets: &mut HashMap<HistoryKey, Bucket>, target_len: usize) {
	if buckets.len() <= target_len {
		return;
	}
	let mut by_age: Vec<(Instant, HistoryKey)> = buckets
		.iter()
		.map(|(key, bucket)| (bucket.last_seen, key.clone()))
		.collect();
	by_age.sort_by_key(|(last_seen, _)| *last_seen);
	for (_, key) in by_age.into_iter().take(buckets.len() - target_len) {
		buckets.remove(&key);
	}
}

#[cfg(test)]
mod tests {
	use rmcp::model::MetaObject;
	use serde_json::json;

	use super::*;

	fn backend() -> ResourceName {
		ResourceName {
			name: "mcp".into(),
			namespace: "default".into(),
			kind: None,
		}
	}

	fn request_context() -> IncomingRequestContext {
		let (parts, _) = ::http::Request::new(()).into_parts();
		IncomingRequestContext::new(&parts)
	}

	fn context_with_subject(subject: &str) -> IncomingRequestContext {
		let mut ctx = request_context();
		let claims = crate::http::jwt::Claims {
			inner: json!({"iss": "https://issuer.example", "sub": subject})
				.as_object()
				.cloned()
				.expect("claims object"),
			jwt: Default::default(),
		};
		ctx.extensions_mut().insert(claims);
		ctx
	}

	fn meta_with(value: serde_json::Value) -> RequestMetaObject {
		RequestMetaObject(MetaObject(
			value.as_object().cloned().expect("meta must be an object"),
		))
	}

	#[test]
	fn empty_history_has_no_entries() {
		let store = McpHistoryStore::new();
		let key = HistoryKey::new("default/mcp", "anonymous", None);
		assert!(store.snapshot(&key).is_empty());
		assert!(store.is_empty());
	}

	#[test]
	fn snapshot_returns_records_oldest_first() {
		let store = McpHistoryStore::new();
		let key = HistoryKey::new("default/mcp", "jwt:iss:user-1", None);
		store.record(key.clone(), CallRecord::new("mcp", "increment"));
		store.record(key.clone(), CallRecord::new("mcp", "decrement"));

		let snapshot = store.snapshot(&key);
		let tools: Vec<&str> = snapshot.entries.iter().map(|r| r.tool.as_ref()).collect();
		assert_eq!(tools, ["increment", "decrement"]);
	}

	#[test]
	fn bucket_keeps_only_the_most_recent_entries() {
		let store = McpHistoryStore::with_limits(2, 4, SESSION_TTL);
		let key = HistoryKey::new("default/mcp", "jwt:iss:user-1", None);
		for tool in ["first", "second", "third"] {
			store.record(key.clone(), CallRecord::new("mcp", tool));
		}
		let snapshot = store.snapshot(&key);
		let tools: Vec<&str> = snapshot.entries.iter().map(|r| r.tool.as_ref()).collect();
		assert_eq!(tools, ["second", "third"]);
	}

	#[test]
	fn store_evicts_oldest_bucket_at_capacity() {
		let store = McpHistoryStore::with_limits(4, 1, SESSION_TTL);
		let first = HistoryKey::new("default/mcp", "jwt:iss:user-1", None);
		let second = HistoryKey::new("default/mcp", "jwt:iss:user-2", None);
		store.record(first.clone(), CallRecord::new("mcp", "increment"));
		store.record(second.clone(), CallRecord::new("mcp", "increment"));

		assert_eq!(store.len(), 1);
		assert!(store.snapshot(&first).is_empty());
		assert_eq!(store.snapshot(&second).entries.len(), 1);
	}

	#[test]
	fn principal_prefers_jwt_subject_and_issuer() {
		let ctx = context_with_subject("user-1");
		let key = scope(&backend(), &ctx, None);
		assert!(
			key.as_str().contains("jwt:https://issuer.example:user-1"),
			"unexpected key: {}",
			key.as_str()
		);
	}

	#[test]
	fn anonymous_requests_share_one_bucket_per_backend() {
		let ctx = request_context();
		let key = scope(&backend(), &ctx, None);
		assert!(key.as_str().ends_with("anonymous\u{1f}-"));
	}

	#[test]
	fn conversation_id_from_meta_splits_buckets() {
		let meta = meta_with(json!({ "agentsecuregateway.dev/conversationId": "conv-42" }));
		let ctx = context_with_subject("user-1");

		let with_conversation = scope(&backend(), &ctx, Some(&meta));
		let without_conversation = scope(&backend(), &ctx, None);

		assert!(with_conversation.as_str().ends_with("conv-42"));
		assert!(!without_conversation.as_str().ends_with("conv-42"));
		assert_ne!(with_conversation, without_conversation);
	}
}
