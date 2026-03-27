# AI Data Pipeline Security Audit

A comprehensive security audit framework for multi-stage NLP data annotation pipelines. This project identifies, models, and mitigates attack surfaces in AI/ML data workflows — including **prompt injection**, **data poisoning**, **model extraction**, and **data drift** vectors.

> Built as part of cybersecurity coursework at Pulchowk Campus, Institute of Engineering, with practical inspiration from real-world AI annotation workflows.

## Features
- STRIDE-based threat modeling per pipeline stage
- Risk register with quantitative severity scoring (likelihood × impact)
- Statistical anomaly detection on annotation batches
- ISO 27001 Annex A control mapping
- Prompt injection pattern scanner
- Data poisoning / label flip detector
- Markdown + JSON audit report generation

## Project Structure
```
ai-pipeline-security-audit/
├── src/
│   ├── threat_modeler.py
│   ├── risk_register.py
│   ├── anomaly_detector.py
│   ├── control_mapper.py
│   ├── prompt_injection_scanner.py
│   ├── data_poisoning_detector.py
│   ├── report_generator.py
│   └── utils.py
├── tests/
├── data/samples/
├── docs/
├── configs/pipeline_config.yaml
└── requirements.txt
```

## Installation
```bash
git clone https://github.com/divaspoudel/ai-pipeline-security-audit.git
cd ai-pipeline-security-audit
pip install -r requirements.txt
```

## Usage
```bash
# Full audit
python src/report_generator.py --config configs/pipeline_config.yaml --output reports/audit_report.md

# Scan for prompt injection
python src/prompt_injection_scanner.py --input data/samples/sample_annotations.json

# Detect data poisoning
python src/data_poisoning_detector.py --input data/samples/sample_annotations.json --threshold 0.15
```

## License
MIT
