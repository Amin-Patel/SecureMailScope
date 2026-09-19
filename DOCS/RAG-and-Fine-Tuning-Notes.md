# RAG vs. Fine-Tuning — Notes for the Team

Context: we were discussing how to make the AI explanations in
[`gemini_service.py`](../backend/app/services/gemini_service.py) smarter/more
grounded, and whether that means "training a model." Short answer: not
necessarily. Here's the breakdown.

---

## What RAG actually is

**RAG = Retrieval-Augmented Generation.** It's often confused with fine-tuning,
but it's a different mechanism entirely — the model's weights are never
touched.

At query time, RAG does three things:

1. **Retrieve** — pull relevant documents/chunks from an external knowledge
   source (vector DB, search index, flat files) based on the incoming query.
2. **Augment** — inject that retrieved content into the prompt, alongside the
   user's question.
3. **Generate** — the LLM reads the retrieved material as extra context and
   answers using it.

It's an "open-book exam" — the model isn't taught new facts, it's just handed
the facts right before answering.

### Why RAG over fine-tuning

- No training run, no GPU cluster, no labeled dataset — just an index of
  documents.
- The knowledge source updates instantly (add/remove a doc), no retraining.
- Answers can be grounded/cited in specific retrieved evidence, which reduces
  hallucination.
- Much cheaper and faster to stand up than a training pipeline.

### Where this fits SecureMailScope

Right now, `gemini_service.py` does plain prompting: it stuffs a finding's
title/severity/description/evidence into a prompt and asks Gemini to explain
it. That's **not** RAG.

A RAG version would retrieve relevant reference material — CVE writeups, RFC
excerpts, our own internal knowledge-base articles on "why TLS 1.0 is weak,"
etc. — and inject that into the prompt before asking Gemini to explain the
finding. The explanation would then be grounded in real reference material
instead of just the model's parametric knowledge.

---

## What fine-tuning is (and isn't)

Fine-tuning adjusts a model's actual weights so it gets better at a specific
task. Two flavors:

- **Full fine-tuning** — update every parameter. For an 8B model this needs
  roughly: 16GB for weights + 16GB for gradients + ~64GB for Adam optimizer
  state (momentum + variance) + activation memory. **90GB+ VRAM**, multi-GPU
  data-center territory.
- **LoRA / QLoRA** — freeze the base model, train small low-rank adapter
  matrices on top (often <1% of total params). QLoRA additionally loads the
  frozen base in 4-bit. For an 8B model this fits in roughly **10-14GB VRAM**
  — a single consumer GPU.

### Can we do this on our hardware?

Checked against a dev machine: RTX 5080 (16GB VRAM), 32GB system RAM, Ryzen 9
9950X3D.

- Full fine-tuning of an 8B model: **not feasible** on this card.
- QLoRA fine-tuning of an 8B model: **feasible**, with headroom.

Tooling for QLoRA on a single consumer GPU: **Unsloth** (easiest, optimized
for this exact setup, ~2x faster/lower-memory than vanilla PEFT),
Hugging Face `peft` + `bitsandbytes` (manual/standard route), or
**Axolotl**/**LLaMA-Factory** (config-driven).

---

## Recommendation / open question for the team

Fine-tuning is the *expensive* path to better AI explanations:

- Requires a labeled dataset of good (finding → explanation) pairs.
- The output is a model we then have to host ourselves, instead of just
  calling the Gemini API.

RAG (or even just better prompting — few-shot examples, retrieved reference
docs) likely gets us most of the value for a fraction of the effort, and
doesn't require us to stand up any training infrastructure or GPU hosting.

Per [`DOCS/Master Website Functionality Map.md`](Master%20Website%20Functionality%20Map.md#28-what-should-not-become-an-mvp-dependency),
**"Full ML training" is explicitly out of scope for the MVP** — so any
fine-tuning work should be treated as a post-MVP/future-expansion track, not
a blocker for the current build.

**Open question for discussion:** do we want to invest in a RAG layer
(retrieval over security reference docs) for the MVP's AI explanations, or
defer both RAG and fine-tuning to a later phase and ship with the current
plain-prompting approach?
