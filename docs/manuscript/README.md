# Reproduce the signed-media verification manuscript

The paper uses the existing Rust cryptography tests on synthetic byte strings.
The tests exercise a valid signature, changed media, a changed artifact index,
and a different verifier key. The project renders their recorded outcomes
through the pinned Docxology Template.

Install rustup with the Rust 1.91.0 toolchain, Git, uv, Pandoc with a compatible
pandoc-crossref, and XeLaTeX. Run these commands from the Steganographer checkout.

```sh
template_dir=/absolute/path/to/template
project_dir="$template_dir/projects/working/steganographer"
git -C "$template_dir" switch --detach 87704feae0a4490ef7dad9c931d268e8c30273c2
mkdir -p "$template_dir/projects/working"
git worktree add --detach "$project_dir" HEAD
cd "$template_dir"
uv sync --locked --python 3.14 --no-dev
(cd "$project_dir" && MPLBACKEND=Agg "$template_dir/.venv/bin/python" -m docs.reproduce_verification)
uv run --no-sync python scripts/pipeline/stage_03_render.py --project working/steganographer
uv run --no-sync python scripts/pipeline/stage_04_validate.py --project working/steganographer
```

The render worktree holds the PDF, HTML, test output, measured results, and
generated figure under `output/`. [Template prerequisites](https://github.com/docxology/template/blob/87704feae0a4490ef7dad9c931d268e8c30273c2/docs/RUN_GUIDE.md)
