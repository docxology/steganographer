# config/

Example and reference TOML configuration files for the steganographer pipeline.

## Files

| File | Size | Description |
| ------ | ------ | ------------- |
| `example.toml` | 2.0 KB | Annotated example with video + audio pipeline config |

## Usage

```bash
# Use from CLI
steganographer --config config/example.toml encode --input file.rgb --output out.rgb

# Or use the top-level steganographer.toml
steganographer --config steganographer.toml encode ...
```

## Schema

See [docs/configuration.md](../docs/configuration.md) for the full TOML schema reference.
