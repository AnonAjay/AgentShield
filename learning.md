# Engineering Notes

Agent Shield v0.1 is structured to make its security claim narrow and inspectable: a registered tool handler is called only after argument/resource validation, deterministic authorization, and a successful pre-execution audit write.

## Why use a typed core?

ToolCall, AuthorizationContext, SecurityDecision, and SecurityEvent distinguish untrusted proposals from trusted host state and Shield outcomes. Plain dictionaries are easier to begin with, but they make it easier to accidentally treat model claims as permissions or omit decision metadata. Dataclasses and protocols keep the core dependency-free. A larger validation library could offer richer schemas, at the cost of a required dependency and a broader behavior surface.

The request ID is only a correlation value. It is not a nonce, capability, or authorization token. Permissions are supplied by the host and are not inferred from prompts.

## Why is authorization deterministic?

An LLM is useful for proposing work or identifying suspicious behavior, but its response is probabilistic and influenced by untrusted content. The policy engine is ordinary code: registered tool names and host-supplied permissions determine the result. The LLM cannot change that result.

Detection can be probabilistic and still be useful as an advisory layer. It must not be confused with an authorization decision.

## Why fail closed?

If policy evaluation raises an error, the runtime cannot establish permission, so it denies. If the pre-execution audit event cannot be written, the configured default also denies. This favors assurance over availability. Applications that change this behavior would weaken the audit guarantee and should expose that trade-off explicitly.

An error while recording the post-execution event is different: a completed external side effect cannot be undone. The earlier authorization event is written before execution, but the final result may be missing.

## Why retain a small schema subset?

The v0.1 validator handles common request shapes, required fields, extra fields, primitive types, enums, numeric limits, string lengths, filesystem roots, and exact host allowlists. A deliberately small subset can be reviewed and tested. It is not a drop-in JSON Schema implementation. Integrations should reject unsupported schema constructs during setup rather than silently assume they are enforced.

## Why are benchmarks local and mocked?

The benchmark asks whether the security boundary blocks actions and preserves benign operations. A fixed model would introduce nondeterminism, while a live provider or external service would add network cost and confound enforcement timing. Mock handlers give repeatable side-effect signals. This does not measure a model's resistance to prompt injection or production service performance.

## Questions for future engineering work

- What host and filesystem API can make allowed-file access resistant to concurrent symlink changes?
- Should audit sinks support multiple processes, durability levels, rotation, and tamper evidence?
- How should asynchronous integrations preserve the exact same policy path?
- Which static findings are useful enough to keep without raising too many false alarms?
- What real agent evaluation can be repeated safely and reported with clear denominators?
