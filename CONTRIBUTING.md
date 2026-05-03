# Contributing to MAS-Sentry-Toolkit

## Setup

    git clone https://github.com/user70616E6461/mas-sentry-toolkit.git
    cd mas-sentry-toolkit
    pip install -r requirements.txt

## Run tests

    pytest tests/unit/ -v

## Commit convention

    feat(scope):  new feature
    fix(scope):   bug fix
    docs:         documentation
    test(scope):  tests
    refactor:     code restructure
    chore:        maintenance

## Adding a new exploit module

1. Create mas_sentry/exploits/mqtt_yourmodule.py
2. Add unit test in tests/unit/test_yourmodule.py
3. Export from mas_sentry/exploits/__init__.py
4. Document in docs/usage/

## Lab environment

    docker-compose up -d
    python3 -m mas_sentry audit --target 127.0.0.1

## Legal

Only use against systems you own or have written permission to test.
