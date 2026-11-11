# ============================================================
#  IMAGE "APRÈS" — Dockerfile sécurisé (bonnes pratiques)
#
#  Changements par rapport à la version "avant" :
#   1. Image de base MINIMALE et FIGÉE par version (python:3.11-slim
#      au lieu de python:latest) -> surface d'attaque + reproductibilité
#   2. Lint du Dockerfile intégré à la build (hadolint via buildkit ?)
#      -> ici : commentaires + analyse Trivy
#   3. Dépendances installées avec --no-cache-dir et couche nettoyée
#      en une seule RUN (moins de couches, pas de résidus pip)
#   4. COPY ciblée : uniquement app/ et requirements.txt
#      (pas de .git, pas de docs, pas de tests dans l'image)
#   5. Utilisateur NON-ROOT dédié, fichiers dont il est propriétaire
#      via COPY --chown (pas de couche chown qui duplique les fichiers)
#   6. HEALTHCHECK intégré (l'orchestrateur sait si le conteneur est sain)
#   7. Secrets ABSENTS de l'image : ils sont injectés à l'exécution
#      par des variables d'environnement (Secret Kubernetes)
# ============================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utilisateur applicatif non-root, sans shell de login ni mot de passe
RUN groupadd --gid 10001 appgroup \
 && useradd  --uid 10001 --gid appgroup --shell /usr/sbin/nologin --no-create-home appuser

WORKDIR /app

# Dépendances d'abord (meilleur cache de build : la couche ne change
# que si requirements.txt change), nettoyage dans la même couche
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Code applicatif : copie ciblée + ownership direct (pas de chown en couche)
COPY --chown=appuser:appgroup app/app.py /app/app.py

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

# Aucun secret ici : injecté à l'exécution (Secret Kubernetes -> env)
CMD ["python", "app.py"]
