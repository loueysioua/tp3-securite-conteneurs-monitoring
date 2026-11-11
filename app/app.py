"""
Application de démonstration — TP 3 : Sécurité des conteneurs & Monitoring runtime.

L'application ne contient AUCUN secret en dur : tous les secrets sont injectés
par des variables d'environnement, alimentées par un Secret Kubernetes.

Endpoints :
    GET /            -> compteur de visites (token Redis-like en mémoire)
    GET /health      -> statut + preuve que les secrets sont bien chargés (valeur masquée)
    GET /whoami      -> identité de l'utilisateur qui exécute le processus (doit être non-root)
"""
import os
import hashlib
from flask import Flask, jsonify

app = Flask(__name__)

# Les secrets arrivent UNIQUEMENT de l'environnement (Secret Kubernetes -> env).
# Ils ne sont ni écrits dans le code, ni dans l'image, ni dans les logs.
API_KEY = os.environ.get("APP_API_KEY", "")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")

# Compteur en mémoire (pas de dépendance externe : la démo reste autonome)
_hits = 0


def _fingerprint(secret: str) -> str:
    """Empreinte SHA-256 : prouve qu'on connaît le secret sans jamais le révéler."""
    if not secret:
        return ""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def _mask(secret: str) -> str:
    if not secret:
        return "<ABSENT>"
    if len(secret) <= 4:
        return "****"
    return secret[:2] + "****" + secret[-2:]


@app.route("/")
def home():
    global _hits
    _hits += 1
    return (
        f"Bonjour ! Cette page a été vue {_hits} fois. "
        f"Je suis le conteneur {os.uname().nodename} (utilisateur : {os.environ.get('USER', '?')})"
    ), 200


@app.route("/health")
def health():
    """Endpoint utilisé par les probes Kubernetes ET par la démo des secrets."""
    return jsonify(
        {
            "status": "ok",
            "secrets": {
                "APP_API_KEY": {
                    "présent": bool(API_KEY),
                    "valeur_masquée": _mask(API_KEY),
                    "empreinte_sha256": _fingerprint(API_KEY),
                },
                "REDIS_PASSWORD": {
                    "présent": bool(REDIS_PASSWORD),
                    "valeur_masquée": _mask(REDIS_PASSWORD),
                },
            },
            "process": {
                "uid": os.getuid(),
                "non_root": os.getuid() != 0,
            },
        }
    ), 200


@app.route("/whoami")
def whoami():
    return jsonify(
        {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "user": os.environ.get("USER", "?"),
            "home": os.environ.get("HOME", "?"),
            "hostname": os.uname().nodename,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
