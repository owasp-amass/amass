# Local classification baseline

This package implements a **provider-independent two-class linear classifier** with bounded feature vectors, strict JSON model loading, explicit uncalibrated softmax scores, and decisions: `skip`, `review`, `escalate`.

It has no external inference libraries, performs no network requests, and cannot change OAM edges. A `skip` decision means not spending a generative-model call on that candidate in a triage workflow; it does **not** prove no relationship exists. `review` is a queue decision, not an accepted relationship.

The classifier is intentionally **not auto-wired into the inference scanner** yet. Doing so before reliable evidence feature extraction and held-out calibration could silently discard actual ownership relationships. A future implementation can provide a tested feature extractor and route only policy-approved, high-confidence negatives locally. An ONNX adapter can implement the same `Classifier` interface, without making CGO mandatory for ordinary Amass installations.

These are baseline components, **not trained production weights**.
