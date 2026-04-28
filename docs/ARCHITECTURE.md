# MAS-Sentry-Toolkit — Architecture (DAY 12)

## Component Map
┌─────────────────────────────────────────┐
│         MAS-Sentry-Toolkit v0.1.0       │
└─────────────────────────────────────────┘
┌─────────┐
          │   CLI   │  sniff / audit / abfp
          └────┬────┘
               │
     ┌─────────▼──────────┐
     │   SentryEngine     │
     │  core/engine.py    │
     └──┬─────────────────┘
        │
┌────────▼────────┐
│   ScanSession   │
│  core/session   │
└──┬──────────────┘
│
┌────┴──────────────────────────────┐
│             │                     │
▼             ▼                     ▼
display     exporter          Protocol Layer
core/       core/             protocols/
display.py  exporter.py
│                 MQTTAnalyzer
severity    .to_json()        AMQPAnalyzer
color       .to_md()          TopicWalker
table                         BruteForcer
panel                         RetainedScan

## Data Flow

Target → Protocol Analyzer → ScanSession.add_finding()
│
┌─────────▼──────────┐
│   ReportExporter    │
│  .to_json()  → *.json
│  .to_md()    → *.md
│  .to_html()  → Day 26
└─────────────────────┘

## Module Status

| Module                         | Status  | Day |
|--------------------------------|---------|-----|
| core/config.py                 | ✅ Done | 2   |
| core/session.py                | ✅ Done | 2   |
| core/engine.py                 | ✅ Done | 2   |
| core/display.py                | ✅ Done | 12  |
| core/exporter.py               | ✅ Done | 12  |
| protocols/base.py              | ✅ Done | 4   |
| protocols/mqtt_analyzer.py     | ✅ Done | 5   |
| protocols/mqtt_fingerprint.py  | ✅ Done | 6   |
| protocols/mqtt_topic_walker.py | ✅ Done | 6   |
| protocols/mqtt_retained.py     | ✅ Done | 6   |
| protocols/amqp_analyzer.py     | ✅ Done | 7   |
| exploits/mqtt_bruteforce.py    | ✅ Done | 8   |
| exploits/mqtt_fuzzer.py        | ✅ Done | 9   |
| agents/fingerprinter.py        | 🔄 Next | 15  |
| threat_modeling/stride.py      | 🔄 Next | 22  |
| reporting/html_report.py       | 🔄 Next | 26  |
