# Exact organization lookup and deterministic subsidiary questions

The experimental AI agent now exposes the read-only `lookup_organization`
tool. It uses an exact name filter through the Asset Database repository,
not an unbounded scan. The query returns up to ten matches and asks for
disambiguation if a name maps to multiple organizations.

For this narrow question form:

```text
What subsidiaries does Acme Holdings Inc. have?
```

the agent resolves the organization name, executes an outgoing, depth-one,
bounded `subsidiary` traversal, and returns the stored OAM relationships
with asset and edge IDs. **No LLM call is required** for this deterministic
question. It therefore also works with Ollama models that do not reliably
choose tools, and incurs no generative-model token cost.

This is not a general-purpose natural-language-to-graph parser. Questions
outside the direct-subsidiary pattern still use a model to select tools.
If that model initially returns no tool calls, the agent retries once with
a stronger instruction; it fails closed on a second ungrounded answer.
Ollama's OpenAI-compatible endpoint currently does not support
`tool_choice: required`, so simply setting that parameter is insufficient.

Negative results mean that the specified database contains no matching
stored relationships. They do **not** establish that a legal entity has
no subsidiaries in the real world. An unknown or ambiguous company name
is reported as incomplete, and truncated traversals are disclosed.
