#!/usr/bin/env bash
# ============================================================
# Scan des images Docker avec Trivy (lancé 100% en conteneur :
# rien à installer sur la machine hôte).
# Génère :
#   reports/scan-avant.txt  (tableau lisible — image avec défauts)
#   reports/scan-avant.json (format machine)
#   reports/scan-secure.txt / reports/scan-secure.json
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p reports

# Le cache est conservé dans un volume Docker (pas d'installation hôte)
docker volume create trivy-cache >/dev/null 2>&1 || true

for TAG in avant secure; do
  echo "== Scan Trivy de tp3-app:${TAG} =="
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v trivy-cache:/root/.cache/ \
    aquasec/trivy:0.76.2 image \
      --ignore-unfixed \
      --severity HIGH,CRITICAL \
      tp3-app:${TAG} > reports/scan-${TAG}.txt || true

  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v trivy-cache:/root/.cache/ \
    aquasec/trivy:0.76.2 image \
      --ignore-unfixed \
      --format json \
      tp3-app:${TAG} > reports/scan-${TAG}.json || true

  echo "   -> reports/scan-${TAG}.txt / reports/scan-${TAG}.json"
done

echo ""
echo "=== Résumé (vulnérabilités HIGH/CRITICAL) ==="
for TAG in avant secure; do
  echo "--- tp3-app:${TAG} ---"
  grep -E "^Total:|^   (HIGH|CRITICAL|MEDIUM|LOW)|^Maximum" reports/scan-${TAG}.txt || true
done
