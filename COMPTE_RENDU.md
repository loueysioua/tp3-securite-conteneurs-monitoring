# Compte rendu — TP 3 : Sécurité des Conteneurs et Monitoring en Runtime

**Auteur :** Louey Sioua
**Durée réelle :** ~4h (dont une bonne partie passée à déboguer Falco, voir §5)
**Repo :** https://github.com/loueysioua/tp3-securite-conteneurs-monitoring
**Contrainte respectée :** tout le TP tourne via Docker, sans rien installer sur la machine hôte.

---

## 0. Contexte et choix techniques

L'énoncé demandait un cluster de démonstration (Minikube ou équivalent) et des outils
de scan/détection. Plutôt que d'installer kubectl, minikube, trivy ou falco sur la
machine, j'ai tout embarqué dans des conteneurs :

| Outil | Mise en œuvre |
|---|---|
| Cluster Kubernetes | conteneur Docker **k3s** (node complet, single-node) |
| kubectl | fourni **dans** le conteneur k3s → `docker exec k3s kubectl …` |
| Trivy | conteneur `aquasec/trivy` lancé à la demande, cache dans un volume Docker |
| Falco | **DaemonSet dans le cluster**, driver eBPF moderne (aucun module noyau) |

C'est aussi ce qui rend la démo rejouable n'importe où : un seul `make cluster` et
l'environnement complet remonte.

---

## Partie 1 — Sécurité de l'image Docker

### 1.1 L'image de départ (« avant »)

Le point de départ reproduit les défauts classiques d'un projet hérité d'un ancien TP
(`docker/Dockerfile.avant`) :

- base `python:latest` : tag flottant (build non reproductible) + distribution complète ;
- le conteneur tourne en **root** ;
- un **secret d'API en dur** : `ENV APP_API_KEY=sk-live-…` et un fichier
  `app/credentials.json` qui finit dans l'image à cause du `COPY . .` ;
- `COPY . .` copie tout le repo (dont `.git`) dans l'image ;
- pas de HEALTHCHECK.

### 1.2 Scan avec Trivy

Le scan se fait via un conteneur Trivy qui a accès à la socket Docker :

```bash
make build   # construit tp3-app:avant et tp3-app:secure
make scan    # scanne les deux images, rapports dans reports/
```

> 📸 **[CAPTURE 1 — Build des deux images]**
> *Commandes :* `make build` puis `docker images | grep tp3-app`
> *Ce qu'on doit voir :* les deux images `tp3-app:avant` (1.65 GB) et `tp3-app:secure` (193 MB).

> 📸 **[CAPTURE 2 — Rapport Trivy de l'image "avant"]**
> *Commande :* `make scan` (ou `less reports/scan-avant.txt`)
> *Ce qu'on doit voir :* la ligne résumé `Total: 4 (HIGH: 4…)` pour les paquets Debian
> et `Total: 5 (HIGH: 5…)` pour les paquets Python — 9 vulnérabilités HIGH au total,
> sur une base de **470 paquets OS** (les 5 autres viennent des paquets Python).

Résultats comparés :

| | `tp3-app:avant` | `tp3-app:secure` |
|---|---|---|
| Taille de l'image | **1.65 GB** | **193 MB** (−88 %) |
| Paquets OS (Debian) | 470 | 87 |
| Vulnérabilités HIGH | 9 (OS + Python) | 4 |

Petit point d'honnêteté : je m'attendais à des dizaines de CRITICAL dans l'image
« avant », mais `python:latest` pointait au moment du TP sur une Debian 13.7 très
récente, donc peu de CVEs connues. Le vrai argument de l'image durcie n'est pas
seulement le nombre de vulnérabilités : c'est la **surface d'attaque** (470 → 87
paquets), la taille (1.65 GB → 193 MB) et la reproductibilité.

Exemples de CVEs trouvées dans l'image « avant » : CVE-2025-47273, CVE-2026-114613,
CVE-2026-76844 (liste complète dans `reports/scan-avant.txt`).

### 1.3 Le secret, visible dans l'image

Un scan de vulnérabilités ne suffit pas : Trivy détecte aussi les **secrets**. Plus
parlant : le secret est visible à l'œil nu dès le build, et dans l'image finale :

> 📸 **[CAPTURE 3 — Docker signale le secret lors du build]**
> *Commande :* `docker build -f docker/Dockerfile.avant -t tp3-app:avant .`
> *Ce qu'on doit voir :* le warning `SecretsUsedInArgOrEnv: Do not use ARG or ENV
> instructions for sensitive data (ENV "APP_API_KEY")` émis par BuildKit.

> 📸 **[CAPTURE 4 — Le secret lisible dans l'image]**
> *Commande :* `docker history tp3-app:avant | grep -i api_key`
> *Ce qu'on doit voir :* la ligne `ENV APP_API_KEY=sk-live-5f4a2b7c8d9e1f0a3b6c…`.
> N'importe qui récupérant l'image depuis un registry peut lire ce secret.

### 1.4 Le Dockerfile sécurisé et les changements

Le nouveau Dockerfile (`docker/Dockerfile`) applique les bonnes pratiques :

| Changement | Justification |
|---|---|
| Base `python:3.11-slim` (version épinglée) | base minimale → surface d'attaque réduite, build reproductible |
| `PIP_NO_CACHE_DIR=1`, install en une seule couche | pas de cache pip résiduel, moins de couches |
| Utilisateur dédié `appuser` (uid 10001) + `USER` | le processus ne tourne **jamais** en root |
| `COPY --chown=appuser:appgroup` | ownership direct, pas de couche `chown` qui duplique les fichiers |
| Copie **ciblée** (`requirements.txt`, puis `app.py`) | pas de `.git`, pas de docs, pas de `credentials.json` dans l'image |
| `HEALTHCHECK` intégré | l'orchestrateur sait si le conteneur est réellement sain |
| **Secrets supprimés de l'image** | injectés à l'exécution via Secret Kubernetes (Partie 2) |

> 📸 **[CAPTURE 5 — uid root vs uid non-root]**
> *Commandes :*
> ```bash
> docker run --rm tp3-app:avant id
> docker run --rm --entrypoint sh tp3-app:secure -c "id"
> ```
> *Ce qu'on doit voir :* `uid=0(root)` pour l'ancienne image, `uid=10001(appuser)`
> pour la sécurisée.

> 📸 **[CAPTURE 6 — Les couches de la nouvelle image, sans secret]**
> *Commande :* `docker history tp3-app:secure | grep -i api_key`
> *Ce qu'on doit voir :* aucune sortie — plus rien à fuiter.

---

## Partie 2 — Gestion des secrets

### 2.1 Démarche

1. Les secrets (`APP_API_KEY`, `REDIS_PASSWORD`) sont déclarés dans un **Secret
   Kubernetes** (`k8s/00-namespace-et-secret.yaml`), encodés en base64.
2. Ils sont injectés dans les pods via `secretKeyRef` → variables d'environnement.
   Le code (`app/app.py`) ne contient **aucune** valeur, il ne fait que lire l'env.
3. Redis lui-même démarre avec `--requirepass $(REDIS_PASSWORD)`, également alimenté
   par le Secret.
4. Bonus durcissement : les pods tournent avec `runAsNonRoot`, `readOnlyRootFilesystem`,
   `allowPrivilegeEscalation: false` et `capabilities: drop ALL`.

Il faut être honnête sur les limites (question probable du jury) : le base64 n'est
**pas** du chiffrement, quiconque a accès à l'API peut décoder le Secret. En production
on utiliserait Sealed Secrets, SOPS ou HashiCorp Vault.

### 2.2 Déploiement et preuve d'accès aux secrets

```bash
make cluster   # k3s + import des images + apply des manifestes
make app       # état des pods + GET /health
```

> 📸 **[CAPTURE 7 — Les pods en Running]**
> *Commande :* `docker exec k3s kubectl -n tp3 get pods`
> *Ce qu'on doit voir :* 2 pods `app-demo` en `1/1 Running` + 1 pod `redis` en `1/1 Running`.

> 📸 **[CAPTURE 8 — Le Secret et son décodage]**
> *Commande :* `make secrets`
> *Ce qu'on doit voir :* le Secret `app-secrets` (type Opaque, 2 clés), puis la valeur
> décodée de `APP_API_KEY` affichée par la commande `base64 -d` — preuve que le Secret
> est bien monté dans le cluster. (La démo illustre le mécanisme d'injection ; en
> soutenance, mieux vaut le préciser avant de décoder les valeurs.)

L'application expose un endpoint `/health` qui prouve que les secrets sont chargés
**sans jamais les révéler** : valeur masquée + empreinte (16 premiers caractères du
SHA-256) du secret, et l'uid du processus. Autrement dit : on prouve la présence
d'un secret, jamais sa valeur.

> 📸 **[CAPTURE 9 — /health : secrets chargés (masqués), processus non-root]**
> *Commande :* `curl -s http://localhost:30080/health`
> *Ce qu'on doit voir :* `"présent": true`, `"valeur_masquée": "sk****99"`, une
> empreinte (tronquée) `564c7eedf40a2850`, et `"non_root": true, "uid": 10001`.

---

## Partie 3 — Surveillance au runtime avec Falco

### 3.1 Déploiement

Falco tourne en **DaemonSet** sur le cluster (`k8s/02-falco.yaml`), avec :

- driver **eBPF moderne** (`engine.kind=modern_ebpf`) : aucune compilation de module
  noyau, pas besoin des headers Linux de la machine ;
- `privileged: true` + `hostPID: true` : Falco doit voir tous les syscalls et tous les
  processus du nœud ;
- la socket containerd du nœud montée dans le pod : Falco sait quel conteneur, quel
  pod et quel namespace ont généré chaque événement ;
- alertes en JSON sur stdout **et** dans le fichier
  `runtime-data/falco-events/falco-alerts.json`, monté depuis la machine hôte : la
  démo se lit avec un simple `tail`, en restant 100% Docker.

J'ai aussi écrit deux **règles personnalisées** (ConfigMap `falco-custom-rules`) :

| Règle | Priorité | Condition |
|---|---|---|
| Shell lancé dans le conteneur applicatif | **WARNING** | shell (`sh`, `bash`…) dans le pod `app-demo` |
| Shell lancé dans un conteneur quelconque | NOTICE | filet de sécurité sur tout le cluster |

Une application Flask de production n'a aucune raison d'exécuter un shell : toute
occurrence est anormale par définition.

> 📸 **[CAPTURE 10 — Falco déployé et règles chargées]**
> *Commandes :*
> ```bash
> docker exec k3s kubectl -n security get pods
> docker exec k3s kubectl -n security logs ds/falco | head -20
> ```
> *Ce qu'on doit voir :* le pod `falco-xxxxx` (généré par le DaemonSet) en `Running`, et dans les logs
> `Opening 'syscall' source with modern BPF probe.` (les warnings
> `TOCTOU mitigation` sont non-bloquants).

### 3.2 Simulation de l'attaque et détection

L'attaque simulée est le scénario type d'une intrusion : quelqu'un exécute un shell
dans un conteneur de production.

```bash
make attack   # lance sh dans un pod app-demo puis affiche les alertes
make alerts   # (optionnel) suivre les alertes en continu : tail -f
```

> 📸 **[CAPTURE 11 — L'intrusion simulée et l'alerte Falco]**
> *Commande :* `make attack`
> *Ce qu'on doit voir :* le shell exécuté dans le pod (`uid=10001(appuser)`), puis le
> bloc "Lecture des alertes Falco" avec l'alerte JSON :
> `[TP3-ALERTE] Shell execute dans le conteneur applicatif !` en priorité **WARNING**
> identifiant `k8s_pod_name=app-demo-…`, `k8s_ns_name=tp3`, l'image
> `docker.io/library/tp3-app`, la commande `sh -c id; whoami; ls /` et le parent `runc`.

> 📸 **[CAPTURE 12 — Les alertes en direct pendant la démo]**
> *Commande :* dans un premier terminal `make alerts`, dans un second `make attack`
> *Ce qu'on doit voir :* la nouvelle alerte apparaître en direct dans le premier terminal
> environ 2 secondes après l'intrusion. C'est le rendu le plus spectaculaire devant
> un jury.

---

## 4. Évaluation finale

**1. Améliorations de sécurité apportées à l'image Docker.**
Base minimale et épinglée (`python:3.11-slim` au lieu de `python:latest`), exécution
en non-root (uid 10001), copie ciblée du code (plus de `.git`/`credentials.json`
dans l'image), pas de cache pip, HEALTHCHECK, et surtout **retrait des secrets de
l'image**. Mesurable concrètement : 1.65 GB → 193 MB, 470 → 87 paquets, 9 → 4
vulnérabilités HIGH, et `docker history` ne révèle plus aucun secret.

**2. Fonctionnement de la gestion des secrets.**
Les secrets vivent uniquement dans un Secret Kubernetes, injectés en variables
d'environnement via `secretKeyRef` (app et Redis). L'application les lit au runtime,
ne les logge jamais, et le prouve via `/health` (présence + empreinte, valeur masquée).
Limites connues et assumées : base64 ≠ chiffrement, on citerait Vault/Sealed Secrets
en production.

**3. Détection d'une menace par l'outil de surveillance.**
Falco en DaemonSet analyse les syscalls en eBPF. Un simple `kubectl exec … sh` dans
un pod de production déclenche la règle personnalisée « Shell lancé dans le conteneur
applicatif » en WARNING, avec l'identification complète : pod, namespace, image,
commande exécutée et processus parent. L'alerte est disponible en JSON (fichier
partagé avec l'hôte) et dans les logs du pod.

---

## 5. Difficultés rencontrées (et solutions)

C'est la partie sur laquelle j'ai le plus appris — autant la détailler :

1. **`ErrImageNeverPull` au déploiement** — les images construites localement ne
   sont pas visibles par k3s. Cause : k3s a son propre containerd, et l'import via
   `ctr images import` doit se faire dans le **namespace `k8s.io`** (le premier
   essai dans le namespace `k3s` était invisible pour le kubelet). Solution :
   `docker save … | ctr -n k8s.io images import -`.
2. **Redis en `CrashLoopBackOff`** — `setpriv: setresuid failed`. Cause : avec
   `capabilities: drop ALL`, l'entrypoint Redis ne pouvait plus faire de setuid pour
   repasser sous l'utilisateur `redis`. Solution : démarrer directement avec
   `runAsUser: 999` (l'uid de l'image) — le conteneur ne doit de toute façon jamais
   démarrer en root.
3. **Falco refusait de démarrer** — la variable `DRIVER` que j'avais mise ne
   servait à rien : le bon sélecteur est `engine.kind` dans la config falco, et
   l'entrypoint s'attend à `FALCO_DRIVER_LOADER_OPTIONS=modern_ebpf`. Autre piège :
   les `args` Kubernetes **remplacent** le `CMD` de l'image, d'où un étrange
   `exec: -o: invalid option` jusqu'à ce que je remette `falco` en premier argument.
4. **`Plugin requirement not satisfied: container`** — en écrasant tout
   `falco.yaml` j'avais perdu la section plugins de la config par défaut. Solution :
   garder la config de l'image et tout passer en surcharges CLI (`-o …`).
5. **Le plus costaud : SELinux (Fedora)** — même en privilégié, Falco ne voyait pas
   les syscalls (`Initialization issues during scap_init`). Cause : le label
   SELinux confine les conteneurs et bloque l'accès à tracefs/BTF. Solution :
   lancer le conteneur k3s avec `--security-opt label=disable`. Comportement
   différent entre Ubuntu et Fedora : à retenir pour tout TP « runtime security ».
6. **Règle Falco trop ciblée** — ma première condition filtrait sur
   `container.name contains "app-demo"`, mais `container.name` est le nom du
   conteneur (`app`), pas du pod. La bonne approche : combiner `k8s.pod.name` et
   `container.name` (les champs k8s_* sont remplis grâce à la socket containerd).

---

## 6. Ce que le TP m'a appris

Ce que je retiens d'abord, c'est que la sécurité d'une image se mesure : taille,
paquets, vulnérabilités, secrets exposés — et chaque chiffre descend grâce à une
décision concrète du Dockerfile, pas par magie. Ensuite, les secrets n'ont rien à
faire ni dans le code ni dans l'image ; le modèle Kubernetes (Secret → variables
d'environnement) est simple mais il faut connaître ses limites. Enfin, scan et
détection runtime se complètent : Trivy agit avant le déploiement, Falco prend le
relais quand quelqu'un est déjà dedans, aucun des deux ne remplace l'autre.
Détail qui m'a marqué : l'intrus de la Partie 3 atterrit en uid 10001, sur un
système de fichiers en lecture seule et sans capabilities — un conteneur durci
change vraiment le résultat de l'attaque.

## Annexe — Structure du repo

```
├── app/                        # Application Flask (aucun secret en dur)
├── docker/
│   ├── Dockerfile.avant        # Version avec défauts (cible du scan)
│   └── Dockerfile              # Version sécurisée
├── k8s/
│   ├── 00-namespace-et-secret.yaml
│   ├── 01-app-et-redis.yaml
│   └── 02-falco.yaml           # DaemonSet + règles personnalisées
├── scripts/                    # setup-cluster / scan-trivy / simulate-attack / verify-demo
├── reports/                    # Rapports Trivy (txt + json)
├── runtime-data/falco-events/  # Alertes Falco (fichier partagé avec l'hôte)
├── Makefile                    # make build / scan / cluster / app / secrets / attack / alerts
├── COMPTE_RENDU.md             # Ce document
└── README.md                   # Guide technique complet
```

## Annexe — Commandes de démo rapides

```bash
bash scripts/verify-demo.sh   # vérifier que tout est prêt (13 checks)
make scan && make app && make secrets && make attack
```
