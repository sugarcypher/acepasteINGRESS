# Third-party material in HIB

HIB's attack instructions come from two independent public benchmarks. They are redistributed in
`sources/upstream_payloads.json` (built by `sources/build_sources.py`, which records the sha256 of each upstream file)
and embedded in the generated carriers.

## BIPIA
Yi, J. et al. "Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models." (2023).
https://github.com/microsoft/BIPIA - files `benchmark/text_attack_test.json`, `benchmark/code_attack_test.json`.

    MIT License
    Copyright (c) Microsoft Corporation.

## InjecAgent
Zhan, Q. et al. "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents." (2024).
https://github.com/uiuc-kang-lab/InjecAgent - `data/test_cases_dh_base.json`, `data/test_cases_ds_base.json`
("Attacker Instruction"), and the "enhanced" prefix from `data/test_cases_dh_enhanced.json`.

    MIT License
    Copyright (c) 2023 Qiusi Zhan

Both licenses: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

The UA-cloaking fixture keys on AI crawler/fetcher user-agent tokens as published by their operators (the same list
the ai.robots.txt project collects); no code from that project is included.
