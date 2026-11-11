#!/usr/bin/env bash
# ============================================================
# Vérification complète de la démo (chaque étape du TP) :
#   1. images construites            3. secrets dans K8s + app
#   2. cluster k3s opérationnel      4. Falco détecte une intrusion
# ============================================================
set -uo pipefail
cd "$(dirname "$0")/.."
OK=0; KO=0
check() { if [ "$1" = "0" ]; then echo "  [OK] $2"; OK=$((OK+1)); else echo "  [ÉCHEC] $2"; KO=$((KO+1)); fi; }

echo "== Étape 1 : images =="
docker image inspect tp3-app:avant >/dev/null 2>&1; check $? "image tp3-app:avant construite"
docker image inspect tp3-app:secure >/dev/null 2>&1; check $? "image tp3-app:secure construite"
grep -q "CRITICAL" reports/scan-avant.txt 2>/dev/null; check $? "rapport Trivy de l'image 'avant' présent"
grep -q "CRITICAL" reports/scan-secure.txt 2>/dev/null; check $? "rapport Trivy de l'image sécurisée présent"

echo "== Étape 2 : cluster Kubernetes =="
docker exec k3s kubectl get nodes 2>/dev/null | grep -q Ready; check $? "nœud k3s Ready"
docker exec k3s kubectl -n tp3 get pods 2>/dev/null | grep -q "app-demo.*Running"; check $? "pods app-demo Running"
docker exec k3s kubectl -n tp3 get pods 2>/dev/null | grep -q "redis.*Running"; check $? "pod redis Running"

echo "== Étape 3 : secrets & application =="
H=$(curl -s http://localhost:30080/health)
echo "$H" | grep -q '"pr\\u00e9sent":true\|"présent":true'; check $? "app lit les secrets (valeur masquée via /health)"
echo "$H" | grep -q '"non_root":true\|"non_root": true'; check $? "app exécutée en non-root (uid 10001)"
docker exec k3s kubectl -n tp3 get secret app-secrets >/dev/null 2>&1; check $? "Secret Kubernetes 'app-secrets' présent"

echo "== Étape 4 : Falco & détection runtime =="
docker exec k3s kubectl -n security get pods 2>/dev/null | grep -q "falco.*Running"; check $? "pod Falco Running"
BEFORE=$(wc -c < runtime-data/falco-events/falco-alerts.json 2>/dev/null || echo 0)
docker exec k3s kubectl -n tp3 exec deploy/app-demo -- sh -c "id" >/dev/null 2>&1
sleep 5
AFTER=$(wc -c < runtime-data/falco-events/falco-alerts.json 2>/dev/null || echo 0)
[ "$AFTER" -gt "$BEFORE" ]; check $? "Falco a détecté le shell lancé dans le conteneur (alerte générée)"
grep -q "app-demo" runtime-data/falco-events/falco-alerts.json 2>/dev/null; check $? "l'alerte identifie le pod/namespace"

echo ""
echo "Résultat : $OK OK / $KO échec"
[ "$KO" = "0" ] && echo "LA DÉMO EST PRÊTE ✔" || echo "Relancer : make cluster && make scan (voir README)"
exit $KO
