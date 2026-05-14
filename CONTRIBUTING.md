```bash
git clone https://github.com/user70616E6461/mas-sentry-toolkit
cd mas-sentry-toolkit
pip install -r requirements.txt
pip install pytest pytest-cov
```
```bash
# All tests
pytest tests/unit/ -v
pytest tests/unit/ --cov=mas_sentry --cov-report=term-missing
pytest tests/unit/test_stride.py -v
```

## Project Structure
mas_sentry/
├── core/           # Engine, session, config, types
├── protocols/      # MQTT and AMQP analyzers
├── agents/         # ABFP fingerprinting engine
├── exploits/       # Exploit modules
├── threat_modeling/# STRIDE, CVSS, attack trees
└── reporting/      # HTML, JSON, Markdown reports
tests/
├── unit/           # Unit tests (82+ passing)
└── integration/    # Integration tests vs Docker lab
lab/                # Docker lab (mosquitto + agents)
scripts/            # Utility scripts
docs/               # Methodology and API docs
## Commit Convention
feat(scope):     new feature
fix(scope):      bug fix
test(scope):     tests
docs(scope):     documentation
refactor(scope): code restructure
chore:           maintenance
ci:              CI/CD changes
## Pull Request Checklist

- [ ] Tests pass locally: `pytest tests/unit/ -v`
- [ ] New code has tests
- [ ] Commit messages follow convention
- [ ] No secrets or credentials in code
