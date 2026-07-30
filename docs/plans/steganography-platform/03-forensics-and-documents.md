# Forensics and Document Analysis

## Objective

Provide a read-only, evidence-oriented scanning framework for media, text,
containers, OOXML, and PDF. The framework should transfer ST3GG's breadth and
registry pattern without transferring heuristic overconfidence, unbounded work,
or monolithic implementation.

Document scanning is detection-first. Document embedding is a separate,
experimental decision.

The first document vertical slice is WordprocessingML (`.docx`/`.docm`). The
package-topology layer is shared with SpreadsheetML and PresentationML so
`.xlsx`/`.xlsm` and `.pptx`/`.pptm` can be added without another ZIP parser.

## Trust model

Every input is attacker-controlled:

- file type and extension may disagree;
- lengths, offsets, counts, compression ratios, nesting, and relationships may
  be malicious;
- archives may contain duplicate names, traversal paths, symlinks, or bombs;
- XML may contain entity-expansion or external-reference attacks;
- metadata may be invalid or intentionally confusing;
- a detector may receive gigabytes of noise designed to consume CPU.

Scanning never executes macros, scripts, embedded objects, external links,
fonts, or media. Network access is off by default and unnecessary for standard
analysis.

## Result model

All detectors return a shared schema:

```text
ScanReport
  schema_version
  scan_id
  input identity and observed media type
  profile, limits, elapsed work
  findings[]
  skipped_detectors[]
  truncation/resource-limit events[]
  aggregate assessment

Finding
  finding_id
  detector_id and detector_version
  category and technique
  severity
  confidence score and calibration label
  carrier part and precise location
  evidence[]
  bounded decoded preview
  explanation and false-positive considerations
  remediation
  parent/child finding relationship
```

`severity` describes potential impact. `confidence` describes evidentiary
strength. They must not be merged.

Aggregate assessment is `clean_at_selected_depth`, `findings`, `inconclusive`,
or `truncated`; it never claims universal absence of steganography.

## Detector contract

```rust
pub trait Detector: Send + Sync {
    fn metadata(&self) -> &'static DetectorMetadata;
    fn supports(&self, target: &ScanTarget) -> Support;
    fn estimate(&self, target: &ScanTarget) -> WorkEstimate;
    fn scan(
        &self,
        target: &ScanTarget,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<Finding>, ScanError>;
}
```

Detector metadata includes:

- stable ID and version;
- input types;
- scan depth;
- expected CPU/memory/I/O cost;
- whether extraction is possible;
- confidence calibration source;
- applicable limitations.

Registration is explicit. Duplicate IDs fail tests/startup.

## Scan profiles and budgets

| Profile | Intent | Typical work |
| --- | --- | --- |
| `quick` | File triage | probe, signatures, metadata, cheap text checks |
| `standard` | Default investigation | core statistical/media/container/document detectors |
| `deep` | Explicit expensive review | broad parameter search, recursive media, visual planes |
| `custom` | Automation | exact allowlist/denylist and caller budgets |

Budgets include:

- maximum input and decoded bytes;
- maximum archive entries and aggregate expansion;
- maximum nesting and relationship traversal depth;
- maximum detector wall time/work units;
- maximum image pixels, frames, audio samples, and XML nodes;
- maximum findings and preview bytes;
- maximum parameter combinations for automatic extraction.

Budget exhaustion creates a structured event and `inconclusive`/`truncated`
status. It is not silently treated as clean.

## Detector families

### General file/container

- extension, MIME, magic, and parser disagreement;
- unexpected trailing/prefix data;
- embedded file signatures;
- entropy and regional entropy changes;
- suspicious length, offset, overlap, or duplicate-entry structures;
- archive path traversal, symlink, bomb, and malformed-directory indicators;
- checksums and metadata inconsistencies.

### Text and Unicode

- zero-width and default-ignorable characters;
- variation selectors;
- homoglyph/confusable substitutions;
- bidi controls and direction changes;
- unusual combining-mark density/order;
- non-breaking, thin, and patterned whitespace;
- capitalization, spacing, or punctuation channels;
- suspicious normalization differences;
- bounded extraction previews for recognized encodings.

Reports show escaped code points and normalized comparisons. The scanner never
rewrites the original during analysis.

### Image/media

- canonical magic/locator probes;
- chi-square, SPA, RS, and combined local analysis;
- per-component LSB distributions;
- bit-plane visualization artifacts;
- palette ordering/unused entries;
- PNG chunk ordering, private chunks, IDAT anomalies, and trailing bytes;
- JPEG marker/comment/application data and coefficient-domain indicators;
- audio sample LSB statistics and spectral anomalies;
- known packet extraction with explicit or discovered configurations.

The existing core analysis functions become registered detectors rather than
being reimplemented in the CLI.

### Expansion catalog

These ST3GG-inspired detector families remain modular backlog rather than being
forced into the first standard scan:

| Family | Scope | Planned tier |
| --- | --- | --- |
| SVG/XML/HTML | comments, hidden/off-canvas text, metadata, data URIs, appended content | standard after safe XML layer |
| TAR/GZIP/general archives | structure, trailing data, embedded signatures, recursive budgets | standard |
| SQLite | header/page structure, free-list/slack/high-entropy anomalies | deep |
| source/code text | whitespace, identifier/case, Unicode/confusable channels | deep |
| Braille/emoji/Hangul/math text | recognized symbol-channel decoding with language-aware evidence | deep |
| PCAP | payload/statistical detection only; no injection or replay | optional defensive feature |
| GIF/BMP/WebP | palette/frame/padding/bit-plane structure | after format adapter |
| executable/binary polyglots | signature overlap and appended/embedded data detection only | optional defensive feature |

Each family gets its own detector IDs, dependency feature, budgets, corpus, and
calibration. “Deep” means opt-in cost, not lower safety standards.

## OOXML plan

OOXML is a ZIP package. Analysis separates package topology, XML semantics,
rendering concealment, text channels, and embedded payloads.

### Package topology

- validate content types and root relationships;
- inventory every part with compressed/uncompressed sizes and hashes;
- identify duplicate names, case collisions, path traversal, unreferenced parts,
  missing targets, cycles, and external relationships;
- inspect ZIP comments, extra fields, data descriptors, central/local header
  disagreement, appended data, and high expansion ratios;
- report macros, OLE, ActiveX, custom XML, embedded packages, signatures, and
  thumbnails without executing them.

### WordprocessingML parts

Traverse, at minimum:

- main document;
- headers and footers;
- footnotes and endnotes;
- comments and comments extensions;
- glossary;
- styles and numbering;
- settings;
- custom properties/custom XML;
- relationships and embedded media.

### SpreadsheetML and PresentationML extensions

After the Word vertical slice:

- SpreadsheetML: hidden/very-hidden sheets, rows/columns/cells, comments/notes,
  custom names, formulas, styles encoding patterns, external links, drawings,
  embedded objects, and logical cell-text Unicode analysis.
- PresentationML: hidden slides, off-canvas/tiny/invisible text, speaker notes,
  comments, alternate text, animations/actions, relationships, and embedded
  media.

These reuse package topology, logical-text mapping, style evidence, and recursive
media orchestration. They do not block v0.9 Word support.

### Concealment and covert channels

- `w:vanish`, web-hidden, tiny/zero-sized text;
- foreground matching background or transparent-like appearance;
- off-page positioning and extreme spacing/scale;
- bidi/direction and language anomalies;
- alternate text, titles, fields, bookmarks, content controls, and instructions;
- tracked insertions/deletions and comments not visible in the final view;
- excessive run fragmentation or style toggles encoding binary patterns;
- unusual `rsid` patterns and ignorable/extension markup;
- Unicode and whitespace detectors applied across logical text while retaining
  XML-part/run locations.

Findings distinguish likely authoring-tool artifacts from high-entropy or
deliberately patterned channels.

### Embedded media recursion

Images and audio are passed to general detectors with:

- parent document/relationship context;
- per-part and aggregate byte budgets;
- digest-based deduplication;
- recursion-depth tracking;
- no automatic extraction to the user's filesystem.

## PDF plan

Initial PDF analysis:

- header/version, EOF markers, trailing data, and incremental revisions;
- xref/trailer consistency and object stream limits;
- attachments, embedded files, JavaScript/actions, forms, and external links;
- metadata/XMP disagreement;
- invisible/off-page/tiny/same-color text indicators;
- image extraction to bounded media detectors;
- alternate streams, comments, and suspicious high-entropy objects.

PDF parsing should use a reviewed, bounded parser dependency or an isolated
adapter. It must not execute rendering code merely to perform the standard scan.

## Extraction policy

Detection and extraction are separate:

- `scan` may include a bounded in-memory preview.
- `decode` returns a validated packet when configuration is known/discovered.
- `extract --output` performs an explicit filesystem write with safe naming,
  overwrite policy, and hashes.
- Nested output is never automatically expanded onto disk.
- Malicious filenames are normalized to display-only metadata unless the caller
  supplies a destination name.

## Confidence calibration

Each heuristic detector needs:

- clean negative corpora across common authoring/export tools;
- known positive fixtures across strengths and sizes;
- recorded thresholds and version;
- false-positive and false-negative estimates;
- limitations in the finding text.

Rule examples:

- exact packet magic plus valid envelope plus digest is high confidence;
- magic alone is low confidence;
- one anomalous statistic is low/medium depending on corpus evidence;
- multiple independent calibrated signals may raise combined confidence;
- an invalid signature is evidence of a packet or corruption, not proof of
  malicious intent.

Aggregate combination must avoid treating correlated LSB tests as independent
probabilities.

## Work packages

| ID | Scope | Depends on | Acceptance |
| --- | --- | --- | --- |
| `FOR-001` | Result schema, registry, budgets | format descriptors | JSON snapshots and duplicate-ID/resource tests |
| `FOR-002` | Existing statistical analyzer adapters | `FOR-001` | CLI/core parity and clean/stego calibration |
| `FOR-003` | General magic/entropy/embedded signatures | `FOR-001` | bounded regional fixtures |
| `FOR-004` | PNG/JPEG/audio structure detectors | formats, `FOR-001` | malformed and real-world negative corpora |
| `FOR-005` | Unicode/text detector family | `FOR-001` | normalization, code-point locations, false positives |
| `FOR-006` | Recursive orchestration | `FOR-001` | depth, bytes, cycles, deduplication, truncation |
| `DOC-001` | Safe OOXML inventory/topology | `FOR-001`, `FOR-006` | malicious ZIP/XML and office-generated fixtures |
| `DOC-002` | WordprocessingML concealment/text | `DOC-001`, `FOR-005` | precise part/run evidence and calibration |
| `DOC-003` | OOXML embedded-media recursion | `DOC-001`, media detectors | parent-linked findings and aggregate limits |
| `DOC-004` | PDF structural standard scan | `FOR-001`, `FOR-006` | revision/object/attachment/media fixtures |
| `FOR-007` | Deep scan parameter search | packet/placement registry | combination/time caps and explicit truncation |
| `DOC-005` | SpreadsheetML/PresentationML extensions | `DOC-001`, `FOR-005` | office-generated clean corpus and precise part evidence |
| `FOR-008` | Modular expansion detector families | relevant safe parsers | per-family feature, limits, fixtures, and calibration |

## Exit criteria

- Standard scanning is deterministic for fixed detector versions and budgets.
- Every finding contains reproducible location and evidence.
- Clean Office/PDF/media corpora establish detector baselines.
- Archive/XML/PDF bombs, cycles, malformed offsets, and excessive findings are
  bounded.
- No scan performs network access, macro/script execution, or implicit file
  extraction.
- CLI, Rust, and WASM use one result schema.
- Documentation never equates “no findings” with proof of no steganography.
