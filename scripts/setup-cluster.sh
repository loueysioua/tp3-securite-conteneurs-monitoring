#!/usr/bin/env bash
# ============================================================
# Déploiement complet du TP — TOUT passe par Docker :
#   - cluster Kubernetes : conteneur k3s ("node" Docker)
#   - images des outils  : importées dans le containerd de k3s
#   - rien à installer sur la machine hôte
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT=$(pwd)

echo "== 1. Démarrage du cluster k3s (conteneur Docker) =="
if ! docker ps --format '{{.Names}}' | grep -q '^k3s$'; then
  docker run -d --privileged --name k3s \
    --security-opt label=disable \
    -p 30080:30080 -p 30090:30090 \
    -e K3S_KUBECONFIG_MODE=666 \
    -v /lib/modules:/lib/modules \
    -v "$PROJECT/runtime-data/falco-events":/data/falco-events \
    rancher/k3s:v1.31.4-k3s1 server \
      --disable traefik --disable servicelb --write-kubeconfig-mode 666
fi

echo "== 2. Attente du nœud =="
until docker exec k3s kubectl get nodes 2>/dev/null | grep -q Ready; do
  sleep 3
done
docker exec k3s kubectl get nodes

echo "== 3. Import des images locales dans le containerd de k3s =="
# k3s utilise son propre containerd : on y importe nos images construites
# localement (trick classique : docker save | ctr images import)
import_image() {
  docker save "$1" | docker exec -i k3s \
    ctr -a /run/k3s/containerd/containerd.sock -n k8s.io images import - >/dev/null
  echo "   importé : $1"
}
import_image tp3-app:secure
import_image falcosecurity/falco:0.45.2
# redis:7-alpine est téléchargé directement par k3s depuis Docker Hub.

echo "== 4. Déploiement des manifestes =="
docker cp "$PROJECT/k8s/." k3s:/k8s/
docker exec k3s kubectl apply -f /k8s/00-namespace-et-secret.yaml
docker exec k3s kubectl apply -f /k8s/01-app-et-redis.yaml
docker exec k3s kubectl apply -f /k8s/02-falco.yaml

echo "== 5. Attente des pods =="
until docker exec k3s kubectl -n tp3 get pods 2>/dev/null | awk '{print $3}' | grep -q Running; do
  sleep 3
done
sleep 5
docker exec k3s kubectl -n tp3 get pods
docker exec k3s kubectl -n security get pods

echo ""
echo "Déploiement terminé. Application : http://localhost:30080/health"
