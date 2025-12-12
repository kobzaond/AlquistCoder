# AlquistCoder

A compact, secure coding assistant and benchmarking suite built around synthetic data, an input-side intention-recognition guardrail, and two new security benchmarks: VulnBench and MalBench.

## Key components
- AlquistCoder coding model (Phi-4-mini–based) plus ModernBERT guardrail for intent classification.
- VulnBench: hard secure-coding prompts selected where multiple strong models produce vulnerable Python.
- MalBench: multi-turn adversarial conversations targeting malicious assistance.
- Code security analysis via Amazon CodeGuru Security and Bandit.

## Repository layout
- codeguru-analyzer/: security scanning utilities, generation and evaluation scripts (CodeGuru, Bandit, vLLM)
- mal_bench/: MalBench evaluation scripts
- vuln_bench/: VulnBench evaluation scripts
- requirements.txt: minimal runtime dependencies
- LICENSE: MIT

## Installation
1. Create a Python 3.10+ environment.
2. Install deps:
   - Review requirements.txt and install: pip install -r requirements.txt
   - Install CodeGuru analyzer helper: cd codeguru-analyzer && pip3 install -e . && cd -
   - Optional: configure AWS credentials for CodeGuru Security (required for CodeGuru evals).

## Quick start
- Run VulnBench evaluations (Bandit + CodeGuru):
  - cd vuln_bench
  - bash run_alquist_vuln_bench.sh
  
- MalBench:
  - cd mal_bench
  - bash eval.sh

Notes
- CodeGuru requires AWS setup; Bandit runs locally.
- Some scripts accept OpenAI/HF tokens for judge/generation (see config.py).
## Models and data
- Models:
  - [CIIRC-NLP/alquistcoder_FINAL_DPO ](https://huggingface.co/CIIRC-NLP/alquistcoder_FINAL_DPO)(coding LLM)
  - [CIIRC-NLP/alquistcoder-intention_recognition-final](https://huggingface.co/CIIRC-NLP/alquistcoder-intention_recognition-final) (ModernBERT guardrail)

- Data: to be released
  #help me fill this in
  - [CIIRC-NLP/alquistcoder2025_DPO_dataset](https://huggingface.co/datasets/CIIRC-NLP/alquistcoder2025_DPO_dataset)
  - [CIIRC-NLP/alquistcoder2025_SFT_dataset](https://huggingface.co/datasets/CIIRC-NLP/alquistcoder2025_SFT_dataset)
  - [CIIRC-NLP/alquistcoder2025_VulnBench](https://huggingface.co/datasets/CIIRC-NLP/alquistcoder2025_VulnBench_dataset)
  - [CIIRC-NLP/alquistcoder2025_MalBench](https://huggingface.co/datasets/CIIRC-NLP/alquistcoder2025_MalBench_dataset)


## Citing
If you use this repo, please cite the AlquistCoder paper:

Kobza et al., "AlquistCoder: A Synthetic Data Approach to Training Compact Secure Coding Assistants and Building Security Benchmarks", 2025.

## License
MIT (see LICENSE).