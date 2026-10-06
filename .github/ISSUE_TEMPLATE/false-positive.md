---
name: False positive
about: A check reported something that is not a weakness
labels: false-positive
---

**Check id**
The `id` field of the finding, for example `authz.idor`.

**What the target actually does**
Why the finding is wrong, in one or two sentences.

**The response that caused it**
Status, relevant headers and enough body to show the shape. Redact anything sensitive.

**What the correct behaviour would be**
Should it not fire at all, or fire with lower confidence?
