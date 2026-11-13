#!/bin/sh
# Stage our own name model for the enclave image.
#
#   enclave/scripts/stage-names-model.sh namemodel/out/xlmr/onnx
#
# Copies the files the enclave loads from namemodel/export.py's folder into
# enclave/names-model/ (gitignored: the weights are private), and writes their
# hashes to enclave/names-model.sha256, which IS committed. The Dockerfile
# copies the model into the image only if every file matches those hashes.
#
# After this: commit enclave/names-model.sha256, then follow RUNBOOK's
# "Updating a running enclave". Its tarball already carries enclave/, so the
# model travels with the source; check the hashes on the host (step 2) as you
# would a source file. The new image has a new PCR0 like any other, and
# /health answers nameModel: "own".
#
# To go back to the two Xenova taggers: delete enclave/names-model/, empty
# names-model.sha256 back to its comments, rebuild.
set -eu
src=${1:?usage: stage-names-model.sh <namemodel export folder>}
root=$(cd "$(dirname "$0")/../.." && pwd)
dst="$root/enclave/names-model"

[ -f "$src/onnx/model_quantized.onnx" ] || { echo "no onnx/model_quantized.onnx in $src: run namemodel/export.py first" >&2; exit 1; }

rm -rf "$dst"
mkdir -p "$dst/onnx"
# What transformers.js reads for a token-classification pipeline at dtype q8,
# plus calibration.json (the softmax temperature train.py fitted).
for f in config.json tokenizer.json tokenizer_config.json special_tokens_map.json calibration.json; do
  [ -f "$src/$f" ] && cp "$src/$f" "$dst/$f"
done
cp "$src/onnx/model_quantized.onnx" "$dst/onnx/model_quantized.onnx"
for f in config.json tokenizer.json tokenizer_config.json; do
  [ -f "$dst/$f" ] || { echo "missing $f in $src" >&2; exit 1; }
done

{
  echo "# Hashes of our own name model's files, as the enclave image must carry them."
  echo "# Written by enclave/scripts/stage-names-model.sh from $src on $(date -u +%Y-%m-%d)."
  (cd "$dst" && find . -type f | sed 's#^\./##' | LC_ALL=C sort | while read -r f; do
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
  done) | sed 's/ \*/  /'   # Windows marks binary files with *; the build reads plain names
} > "$root/enclave/names-model.sha256"

echo "staged $(du -sh "$dst" | cut -f1) in enclave/names-model/"
echo "hashes in enclave/names-model.sha256 — commit that file, not the model"
