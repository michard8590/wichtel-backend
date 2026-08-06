# Wichtel Backend

Freies Backend für die Android-App **Wichtel**.

Das Backend ermöglicht:

- Registrierung ohne Google-Dienste
- Wiederherstellung über Account-Code und Recovery-Key
- Erstellen und Beitreten von Wichtelgruppen
- gruppenbezogene Wunschlisten
- zufällige Wichtelzuteilung
- Speicherung mit SQLite
- Betrieb hinter einem Reverse Proxy
- integriertes Rate Limiting

## Voraussetzungen

- Docker
- Docker Compose
- ein externes Docker-Netz namens `docker_web`
- optional ein Reverse Proxy wie Nginx Proxy Manager

## Installation

Repository klonen und Beispielkonfiguration kopieren:

```bash
cp .env.example .env

Das Docker-Netz anlegen, sofern es noch nicht existiert:

docker network create docker_web

Backend starten:

docker compose up -d --build

Der Dienst ist innerhalb des Docker-Netzes unter Port 8000 erreichbar.

Konfiguration
Variable	Bedeutung	Standard
DATABASE_PATH	Pfad zur SQLite-Datenbank	/app/data/wichtel.db
RATE_LIMIT_ENABLED	Application-Rate-Limiting aktivieren	true
TRUSTED_PROXY_NETWORKS	Vertrauenswürdige Proxy-IP oder Netze	leer

X-Forwarded-For und X-Real-IP werden nur ausgewertet, wenn die direkte Gegenstelle in TRUSTED_PROXY_NETWORKS liegt.

Sicherheit

Der Container:

läuft ohne Root-Rechte
verwendet ein schreibgeschütztes Root-Dateisystem
entfernt alle Linux-Capabilities
aktiviert no-new-privileges
erlaubt Schreibzugriff nur auf /app/data und /tmp
speichert Device-Tokens und Recovery-Keys nur als Hash
begrenzt Geräte, Gruppen, Mitglieder und Wunschlisten
schützt Registrierung, Recovery und Gruppenbeitritt durch Rate Limits
Tests
docker run --rm \
  -v "$PWD:/src:ro" \
  python:3.13-slim \
  sh -euxc '
    mkdir -p /tmp/test-project
    cp -a /src/. /tmp/test-project/
    cd /tmp/test-project
    pip install --no-cache-dir -r requirements-dev.txt
    PYTHONPATH=/tmp/test-project python -m pytest -q
  '
Datensicherung

Vor einer Sicherung sollte eine konsistente SQLite-Kopie erzeugt werden:

docker exec -i wichtel-backend python3 - <<'PY'
import sqlite3

source = sqlite3.connect(
    "/app/data/wichtel.db"
)
target = sqlite3.connect(
    "/app/data/wichtel-backup.db"
)

with target:
    source.backup(target)

source.close()
target.close()
PY

Die erzeugte Datei anschliessend aus dem Datenverzeichnis kopieren und ausserhalb des Repositorys speichern.

Lizenz

Dieses Projekt steht unter der GNU Affero General Public License, Version 3 oder neuer.

Siehe LICENSE.
