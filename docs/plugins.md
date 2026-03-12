# Plugin System

The NLP filter uses a plugin-based architecture for extensible detection. Plugins are registered in `.claude/hooks/plugins/plugins.json` and dispatched by `.claude/hooks/llm_filter.py`.

## Available Plugins

### PII Plugins (first available wins)

| Plugin | Tier | Latency | Install |
|--------|------|---------|---------|
| presidio | SubMillisecond | ~0.4ms | `pip install presidio-analyzer` |
| spacy | EdgeDevice | ~3ms | `pip install spacy && python -m spacy download en_core_web_sm` |
| distilbert | HighAccuracy | ~25ms | `pip install transformers torch` |

### Supplementary Plugins (always run, no deps)

| Plugin | Tier | Latency | What it detects |
|--------|------|---------|-----------------|
| prompt_injection | EdgeDevice | ~1ms | Jailbreak phrases, role reassignment, instruction override |
| sensitive_categories | EdgeDevice | ~1ms | Medical, biometric, and GDPR Art.9 protected categories |
| entropy_detector | EdgeDevice | ~1ms | High-entropy strings (unknown token/secret formats) |
| semantic_intent | EdgeDevice | ~1ms | Verb+target heuristic for suspicious command intent |

## Writing a Custom Plugin

### 1. Create the plugin

Create `.claude/hooks/plugins/my_plugin.py`:

```python
from .base import DetectionResult, SensitiveContentPlugin

class MyPlugin(SensitiveContentPlugin):
    name = "my_plugin"
    tier = "Custom"

    def is_available(self) -> bool:
        try:
            import my_library
            return True
        except ImportError:
            return False

    def detect(self, text, entity_types=None):
        # Return list of DetectionResult
        return []
```

### 2. Register the plugin

Add to `.claude/hooks/plugins/plugins.json`:

```json
{
  "my_plugin": {
    "module": "plugins.my_plugin",
    "class": "MyPlugin",
    "tier": "Custom",
    "latency": "~5ms",
    "description": "My custom detector",
    "install": "pip install my-library"
  }
}
```

### 3. Enable the plugin

Add to `.claude/hooks/llm_filter_config.json`:

```json
{
  "plugin_priority": ["my_plugin", "presidio", "spacy"],
  "plugins": {
    "my_plugin": {
      "enabled": true
    }
  }
}
```

To make a plugin supplementary (always runs alongside the primary PII plugin), add it to `supplementary_plugins` instead of `plugin_priority`.

## Plugin API

All plugins extend `SensitiveContentPlugin` (defined in `.claude/hooks/plugins/base.py`):

| Method | Description |
|--------|-------------|
| `is_available() -> bool` | Return `True` if dependencies are installed |
| `detect(text, entity_types=None) -> list[DetectionResult]` | Run detection, return findings |
| `configure(settings: dict)` | Optional — receive per-plugin settings from config |

`DetectionResult` fields:

| Field | Type | Description |
|-------|------|-------------|
| `entity_type` | str | Category (e.g. `PERSON`, `PROMPT_INJECTION`) |
| `text` | str | The matched text |
| `confidence` | float | 0.0–1.0 confidence score |
| `start` | int | Start offset in input text |
| `end` | int | End offset in input text |
