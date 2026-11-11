# TP 3 — Sécurité des Conteneurs & Monitoring en Runtime

**Application :** `tp3-app` — API Flask (Python) de démonstration, déployée sur un cluster
Kubernetes (k3s) avec gestion des secrets et détection d'intrusion runtime (Falco).

**Contrainte respectée : tout est exécuté via Docker.** Rien n'est installé sur la machine hôte :

| Outil            | Comment il tourne (100% Docker)                                        |
|------------------|------------------------------------------------------------------------|
| Cluster K8s      | Conteneur **k3s** (node Kubernetes complet dans un conteneur Docker)    |
| kubectl          | Binaire présent **dans** le conteneur k3s (`docker exec k3s kubectl …`) |
| Trivy            | Conteneur `aquasec/trivy` (lancé à la volée)                            |
| Falco            | DaemonSet **dans le cluster** (driver eBPF moderne, zéro module noyau)  |

---

## Partie 1 — Sécurité de l'image Docker (1h30)

### 1.1 Scan de l'image « avant » (le point de départ)

L'image d'origine (`docker/Dockerfile.avant`) reproduit les défauts d'un projet hérité :
image de base `python:latest` (non figée, très volumineuse), **processus root**,
**secret d'API en dur** (ENV `APP_API_KEY` + `app/credentials.json` commis dans le repo),
`COPY . .` qui embarque le dépôt Git entier, aucun HEALTHCHECK.

```bash
make build   # construit tp3-app:avant et tp3-app:secure
make scan    # Trivy (en conteneur) scanne les deux images
```

Rapports : `reports/scan-avant.txt` / `reports/scan-secure.txt` (+ versions JSON).

### 1.2 Failles identifiées dans le rapport

- Des dizaines de **vulnérabilités HIGH/CRITICAL** dans la base Debian complète de
  `python:latest` (openssl, glibc, curl…), contre très peu dans la base `slim`.
- `docker history tp3-app:avant` et `docker inspect` révèlent le **secret en clair**
  — Docker lui-même le signale à la build : *SecretsUsedInArgOrEnv*.
- Surface d'attaque élargie : tout le dépôt (`.git`, docs, tests) est dans l'image.
- Le conteneur tourne en **root** (uid 0) : évasion de conteneur = compromission
  totale du nœud.

### 1.3 Changements faits dans le Dockerfile sécurisé (`docker/Dockerfile`)

| # | Changement                                              | Pourquoi                                                             |
|---|---------------------------------------------------------|----------------------------------------------------------------------|
| 1 | `python:3.11-slim` **épinglé** au lieu de `latest`      | base minimale → surface d'attaque réduite, build reproductible       |
| 2 | `ENV PIP_NO_CACHE_DIR=1`, installation en une couche    | pas de résidus de cache pip dans l'image                             |
| 3 | Utilisateur dédié `appuser` (10001), `USER appuser`     | le processus ne tourne **jamais** en root                            |
| 4 | `COPY --chown=appuser:appgroup`                         | ownership direct, pas de couche `chown` qui duplique les fichiers    |
| 5 | `COPY` ciblée (`requirements.txt` puis `app.py`)        | pas de `.git`, pas de docs — rien de superflu dans l'image           |
| 6 | `HEALTHCHECK`                                           | l'orchestrateur sait si le conteneur est réellement sain             |
| 7 | **Secrets retirés de l'image**                          | injectés à l'exécution (Secret K8s) — plus rien à fuiter via `docker history` |

Vérifiable en démo :

```bash
docker history tp3-app:avant | grep -i api_key   # -> le secret est visible
docker run --rm tp3-app:avant sh -c 'id'          # -> uid=0 (root)
docker run --rm tp3-app:secure python -c 'import os; print(os.getuid())'   # -> 10001
```

---

## Partie 2 — Gestion des secrets (1h30)

### 2.1 Démarche

- Les secrets (`APP_API_KEY`, `REDIS_PASSWORD`) sont déclarés dans un **Secret
  Kubernetes** (`k8s/00-namespace-et-secret.yaml`, valeurs en base64).
- Ils sont injectés dans les pods via `secretKeyRef` → **variables d'environnement**,
  jamais dans l'image ni dans le code (`app/app.py` ne contient aucune valeur).
- Redis lui-même démarre avec `--requirepass $(REDIS_PASSWORD)` (secretKeyRef).
- Limites connues (dites au jury !) : base64 ≠ chiffrement ; en production on
  utiliserait **Sealed Secrets / SOPS** ou **HashiCorp Vault**.

### 2.2 Déploiement

```bash
make cluster   # démarre k3s + importe les images + applique les manifestes
make app       # état des pods + GET /health
```

### 2.3 Preuve que l'application accède aux secrets en toute sécurité

L'endpoint `GET /health` prouve que les secrets sont chargés **sans jamais les
révéler** (valeur masquée + empreinte SHA-256) et que le processus est non-root :

```json
{"process":{"non_root":true,"uid":10001},
 "secrets":{"APP_API_KEY":{"présent":true,"valeur_masquée":"sk****99",
            "empreinte_sha256":"564c7eedf40a2850"}, ...}}
```

Démo du Secret côté Kubernetes (aucun outil sur l'hôte, kubectl est dans k3s) :

```bash
make secrets    # affiche le Secret puis décode APP_API_KEY en base64
```

---

## Partie 3 — Surveillance au runtime (1h)

### 3.1 Déploiement de Falco

Falco tourne en **DaemonSet** sur le cluster (`k8s/02-falco.yaml`) :

- driver **eBPF moderne** (`engine.kind=modern_ebpf`) : aucune compilation de
  module noyau, pas de dépendance aux headers Linux ;
- `privileged` + `hostPID` : Falco doit observer **tous** les syscalls du nœud ;
- socket containerd du nœud montée : Falco sait quel conteneur/pod/namespace
  a généré l'événement ;
- alertes écrites dans `runtime-data/falco-events/falco-alerts.json` — fichier
  **monté depuis l'hôte** : la démo se fait avec un simple `tail`, 100% Docker.

Deux règles personnalisées (`k8s/02-falco.yaml` → ConfigMap `falco-custom-rules`) :

| Règle                                        | Priorité | Condition                                                  |
|----------------------------------------------|----------|-------------------------------------------------------------|
| Shell lancé dans le conteneur applicatif     | WARNING  | shell dans le pod `app-demo` (conteneur `tp3-app`)          |
| Shell lancé dans un conteneur quelconque     | NOTICE   | filet de sécurité sur tout le cluster                       |

### 3.2 Simulation de l'attaque + détection

```bash
make attack    # lance un shell dans un pod de prod et affiche les alertes
make alerts    # (optionnel) suivre les alertes en continu
```

Exemple d'alerte générée (fichier JSON) :

```json
{"output":"... [TP3-ALERTE] Shell execute dans le conteneur applicatif !
 (conteneur=app image=docker.io/library/tp3-app shell=sh parent=runc ...)
 k8s_pod_name=app-demo-7bd6b6f58c-blgjq k8s_ns_name=tp3",
 "priority":"Warning", "rule":"Shell lance dans le conteneur applicatif (TP3)"}
```

---

## Évaluation finale — réponses

1. **Améliorations de sécurité de l'image** : base minimale épinglée, non-root
   (uid 10001), copie ciblée, pas de cache pip, HEALTHCHECK, secrets retirés de
   l'image → mesurable : nombre de vulnérabilités HIGH/CRITICAL du rapport Trivy
   et `docker history` qui ne contient plus de secret.
2. **Fonctionnement de la gestion des secrets** : Secret K8s → `secretKeyRef` →
   variables d'environnement → `GET /health` prouve la présence sans révéler la
   valeur ; `make secrets` montre le décodage base64 côté cluster.
3. **Détection d'une menace** : `kubectl exec … sh` dans un pod de prod →
   Falco (eBPF, runtime) déclenche `Shell lance dans le conteneur applicatif`
   en WARNING, en identifiant pod, namespace, image et commande.

---

## Scripts de démo pour la jury (ordre conseillé)

```bash
# 0. Vérifier que tout est prêt (30 s)
bash scripts/verify-demo.sh

# 1. Partie image & scan
make scan                       # rapports Trivy avant/après (tableaux)
grep -i "api_key" <(docker history tp3-app:avant)   # secret visible dans l'ancienne image
docker run --rm tp3-app:avant id; docker run --rm tp3-app:secure id   # root vs non-root

# 2. Partie secrets
make app                        # /health : secrets chargés (masqués), non-root
make secrets                    # le Secret K8s + son décodage

# 3. Partie runtime
docker exec -it k3s kubectl -n tp3 get pods          # l'app tourne
make attack                     # intrusion simulée -> alerte Falco
make alerts                     # (optionnel) stream des alertes
```

## Dépannage rapide

| Symptôme                          | Solution                                        |
|-----------------------------------|-------------------------------------------------|
| `ErrImageNeverPull` au déploiement| relancer `make cluster` (réimport des images)   |
| port 30080 occupé                 | changer `nodePort` dans `k8s/01-app-et-redis.yaml` + `-p` du conteneur k3s |
| Falco ne génère pas d'alerte      | `make falco-logs` ; sur Fedora/RHEL le conteneur k3s doit être lancé avec `--security-opt label=disable` (c'est fait dans `scripts/setup-cluster.sh`) |
| scans Trivy vides                 | relancer `make scan` (le premier scan télécharge la base de CVEs) |

## Structure du repo

```
├── app/                    # Application Flask (aucun secret en dur)
│   └── app.py
├── docker/
│   ├── Dockerfile.avant    # Version héritée avec défauts (scan cible)
│   └── Dockerfile          # Version sécurisée
├── k8s/
│   ├── 00-namespace-et-secret.yaml
│   ├── 01-app-et-redis.yaml
│   └── 02-falco.yaml       # DaemonSet + règles personnalisées
├── scripts/
│   ├── setup-cluster.sh    # k3s en Docker + import images + apply
│   ├── scan-trivy.sh       # scans Trivy en conteneur
│   ├── simulate-attack.sh  # intrusion simulée + lecture des alertes
│   └── verify-demo.sh      # vérification bout-en-bout de la démo
├── reports/                # rapports Trivy (txt + json)
├── runtime-data/falco-events/  # alertes Falco (fichier partagé avec l'hôte)
└── Makefile
```
