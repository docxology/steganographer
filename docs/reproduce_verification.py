"""Render the observed outcomes from the core signature verification tests."""

import json
from pathlib import Path
import subprocess

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
CONTROLS = (
    ("Matching key, video and audio", "test_sign_and_verify", "Accept"),
    ("Matching key, video only", "test_verify_without_audio", "Accept"),
    ("Changed video", "test_tamper_detection_data", "Reject"),
    ("Changed artifact index", "test_tamper_detection_index", "Reject"),
    ("Different public key", "test_wrong_key_fails", "Reject"),
)


def main() -> None:
    command = [
        "cargo", "+1.91.0", "test", "-p", "steganographer-core",
        "--no-default-features", "--locked", "--lib", "crypto::tests",
    ]
    result = subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
    outcomes = []
    for control, test, response in CONTROLS:
        identifier = f"crypto::tests::{test}"
        if f"test {identifier} ... ok" not in result.stdout:
            raise ValueError(f"Required signature control was not confirmed: {identifier}")
        outcomes.append({"control": control, "test": identifier, "verifier_response": response})

    output = ROOT / "output"
    data = output / "data"
    figures = output / "figures"
    data.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    (data / "verification-test-output.txt").write_text(result.stdout)
    receipt = {
        "test_source": "steganographer-core/src/crypto.rs",
        "command": command,
        "controls": outcomes,
    }
    (data / "verification-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")

    figure, axes = plt.subplots(figsize=(7.2, 3.8))
    axes.axis("off")
    axes.text(0.04, 0.92, "Control", fontsize=12, weight="bold")
    axes.text(0.72, 0.92, "Verifier response", fontsize=12, weight="bold")
    for index, outcome in enumerate(outcomes):
        y = 0.78 - index * 0.15
        axes.axhline(y - 0.04, color="#dde3e9", linewidth=1)
        axes.text(0.04, y, outcome["control"], fontsize=11)
        response = outcome["verifier_response"]
        color = "#176449" if response == "Accept" else "#9b332c"
        axes.text(0.72, y, response, color=color, fontsize=11, weight="bold")
    figure.savefig(figures / "verification-controls.png", dpi=170, bbox_inches="tight")
    plt.close(figure)

    registry = {"figures": [{
        "label": "fig:verification-controls",
        "filename": "verification-controls.png",
        "caption": "Verifier responses confirmed by the Rust tests.",
        "alt_text": "Both matching-key tests accepted. Changed video, changed index and a different key rejected.",
        "generated_by": "python -m docs.reproduce_verification",
    }]}
    (figures / "figure_registry.json").write_text(json.dumps(registry, indent=2) + "\n")
    print("Verified the matching-key controls and all three rejection controls.")


if __name__ == "__main__":
    main()
