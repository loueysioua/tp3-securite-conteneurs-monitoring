#!/usr/bin/env bash
# ============================================================
# PARTIE 3 — Démonstration de détection runtime par Falco.
#
# Simule un comportement malveillant : lancement d'un shell
# interactif dans un conteneur applicatif en production.
# Falco (DaemonSet sur le cluster) doit générer une alerte,
# visible :
#   - dans runtime-data/falco-events/falco-alerts.json (fichier,
#     monté depuis la machine hôte — 100% Docker côté hôte)
#   - dans les logs du pod : kubectl logs -n security ds/falco
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Simulation d'une intrusion : shell exécuté dans le pod applicatif =="
POD=$(docker exec k3s kubectl -n tp3 get pod -l app=app-demo -o jsonpath='{.items[0].metadata.name}')
echo "   pod cible : $POD"
docker exec k3s kubectl -n tp3 exec "$POD" -- sh -c "id; whoami; ls /"

echo ""
echo "== Lecture des alertes Falco (5 dernières) =="
sleep 4
if [ -s runtime-data/falco-events/falco-alerts.json ]; then
  tail -n 5 runtime-data/falco-events/falco-alerts.json
else
  echo "Aucune alerte dans le fichier — vérifier : docker exec k3s kubectl -n security logs ds/falco"
fi
