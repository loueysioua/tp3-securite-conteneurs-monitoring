# ============================================================
# Makefile TP3 — tout passe par Docker (aucun outil installé sur l'hôte)
# ============================================================
.PHONY: build build-avant scan cluster deploy app falco attack secrets logs clean

# ---------- Partie 1 : image & scan ----------
build:            ## Construit les deux images (avant = avec défauts, secure = durcie)
	docker build -f docker/Dockerfile.avant -t tp3-app:avant .
	docker build -f docker/Dockerfile -t tp3-app:secure .

build-avant:      ## Construit uniquement l'image "avec défauts"
	docker build -f docker/Dockerfile.avant -t tp3-app:avant .

scan:             ## Scan Trivy des deux images (Trivy lui-même tourne en conteneur)
	bash scripts/scan-trivy.sh

# ---------- Partie 2 & 3 : cluster, secrets, Falco ----------
cluster:          ## Démarre le cluster Kubernetes k3s (en conteneur Docker)
	bash scripts/setup-cluster.sh

deploy:           ## (Ré)déploie l'app + secrets + Falco sur le cluster
	docker cp k8s/. k3s:/k8s/
	docker exec k3s kubectl apply -f /k8s/
	docker exec k3s kubectl -n tp3 get pods
	docker exec k3s kubectl -n security get pods

app:              ## Montre les pods + interroge l'application
	docker exec k3s kubectl -n tp3 get pods
	@echo "--- GET /health (secrets chargés, valeur masquée) ---"
	@curl -s http://localhost:30080/health | python3 -m json.tool 2>/dev/null \
		|| curl -s http://localhost:30080/health

secrets:          ## Montre le Secret Kubernetes et sa décodage (démonstration)
	docker exec k3s kubectl -n tp3 get secret app-secrets
	@echo "--- valeur décodée de APP_API_KEY ---"
	docker exec k3s sh -c 'kubectl -n tp3 get secret app-secrets -o jsonpath="{.data.APP_API_KEY}" | base64 -d; echo'

attack:           ## Simule une intrusion (shell dans un conteneur de prod)
	bash scripts/simulate-attack.sh

alerts:           ## Affiche les alertes Falco en continu (Ctrl-C pour quitter)
	tail -f runtime-data/falco-events/falco-alerts.json

falco-logs:       ## Logs du pod Falco (sortie stdout des alertes)
	docker exec k3s kubectl -n security logs ds/falco -f

# ---------- Divers ----------
clean:            ## Supprime le cluster et les données de démo
	docker rm -f k3s 2>/dev/null || true
	rm -rf runtime-data/falco-events/*.json 2>/dev/null || true
