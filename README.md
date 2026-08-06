# Wichtel Backend

Freies REST-Backend für die Android-App **Wichtel**.

Das Backend basiert auf FastAPI und SQLite. Es ermöglicht die Registrierung ohne Google-Dienste, das Erstellen und Beitreten von Wichtelgruppen, gruppenbezogene Wunschlisten und eine zufällige Wichtelzuteilung ohne Selbstzuweisung.

## Funktionen

- Benutzerkonto ohne E-Mail-Adresse oder externe Anmeldung
- Wiederherstellung über Account-Code und Recovery-Key
- Gerätebasierte Authentifizierung mit Bearer-Token
- Wichtelgruppen erstellen, bearbeiten, verlassen und löschen
- Gruppenbeitritt über Einladungscode
- Verwaltung von Gruppenmitgliedern
- Zufällige Auslosung ohne Selbstzuweisung
- Gruppenbezogene Wunschlisten
- Schutz ausgeloster Gruppen vor nachträglichen Änderungen
- Rate Limiting für sensible Endpunkte
- Automatische OpenAPI-Dokumentation
- Persistente Speicherung mit SQLite
- Betrieb mit Docker Compose hinter einem Reverse Proxy

## Technologie

- Python 3.13
- FastAPI
- Pydantic
- SQLite
- Uvicorn
- Docker und Docker Compose
- Pytest

## Projektstruktur

```text
app/
├── main.py
├── auth.py
├── config.py
├── database.py
├── identifiers.py
├── rate_limit.py
├── schemas.py
├── security.py
├── time_utils.py
├── validation.py
└── routers/
    ├── health.py
    ├── users.py
    ├── groups.py
    ├── wishlists.py
    └── draw.py

tests/
└── test_api_security.py
```

## Voraussetzungen

- Docker
- Docker Compose
- ein externes Docker-Netz namens `docker_web`
- optional ein Reverse Proxy wie Nginx Proxy Manager

## Installation

Repository klonen:

```bash
git clone https://github.com/michard8590/wichtel-backend.git
cd wichtel-backend
```

Beispielkonfiguration kopieren:

```bash
cp .env.example .env
```

Das externe Docker-Netz anlegen, sofern es noch nicht existiert:

```bash
docker network create docker_web
```

Backend bauen und starten:

```bash
docker compose up -d --build
```

Status und Logs anzeigen:

```bash
docker compose ps
docker compose logs -f
```

Backend stoppen:

```bash
docker compose down
```

Der Dienst ist innerhalb des Docker-Netzes unter Port `8000` erreichbar. Die SQLite-Datenbank wird im persistenten Datenverzeichnis unter `/app/data` gespeichert.

## Konfiguration

Die Konfiguration erfolgt über Umgebungsvariablen, typischerweise in der Datei `.env`.

| Variable | Bedeutung | Standard |
|---|---|---|
| `DATABASE_PATH` | Pfad zur SQLite-Datenbank | `/app/data/wichtel.db` |
| `RATE_LIMIT_ENABLED` | Application-Rate-Limiting aktivieren | `true` |
| `TRUSTED_PROXY_NETWORKS` | Vertrauenswürdige Proxy-IP-Adressen oder Netze | leer |
| `MAX_ACTIVE_DEVICES_PER_USER` | Maximale Anzahl aktiver Geräte pro Benutzer | siehe `app/config.py` |
| `MAX_OPEN_GROUPS_PER_OWNER` | Maximale Anzahl offener Gruppen pro Besitzer | siehe `app/config.py` |
| `MAX_GROUP_MEMBERS` | Maximale Anzahl Mitglieder pro Gruppe | siehe `app/config.py` |
| `MAX_WISHLIST_ITEMS_PER_USER_GROUP` | Maximale Anzahl Wünsche pro Benutzer und Gruppe | siehe `app/config.py` |

`X-Forwarded-For` und `X-Real-IP` werden nur ausgewertet, wenn die direkte Gegenstelle in `TRUSTED_PROXY_NETWORKS` liegt.

## Lokale Entwicklung

Virtuelle Umgebung erstellen und Abhängigkeiten installieren:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --requirement requirements.txt
```

Für einen lokalen Start einen beschreibbaren Datenbankpfad setzen:

```bash
export DATABASE_PATH=/tmp/wichtel-development.db
```

Anwendung starten:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

## Authentifizierung

Geschützte Endpunkte erwarten das Geräte-Token im HTTP-Header:

```http
Authorization: Bearer DEVICE_TOKEN
```

Das Geräte-Token wird bei der Registrierung oder Wiederherstellung ausgegeben. Geräte-Token und Recovery-Keys werden nur als Hash in der Datenbank gespeichert.

## API-Endpunkte

### System

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/api/health` | Status des Backends |

### Benutzer

| Methode | Pfad | Beschreibung |
|---|---|---|
| `POST` | `/api/users/register` | Benutzer registrieren |
| `POST` | `/api/users/recover` | Benutzerkonto wiederherstellen |
| `PATCH` | `/api/users/me` | Eigenes Profil bearbeiten |
| `DELETE` | `/api/users/me` | Eigenes Benutzerkonto löschen |

### Gruppen

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/api/groups` | Eigene Gruppen auflisten |
| `POST` | `/api/groups` | Gruppe erstellen |
| `POST` | `/api/groups/join` | Einer Gruppe beitreten |
| `GET` | `/api/groups/{group_id}` | Gruppendetails abrufen |
| `PATCH` | `/api/groups/{group_id}` | Gruppe bearbeiten |
| `DELETE` | `/api/groups/{group_id}` | Gruppe löschen |
| `DELETE` | `/api/groups/{group_id}/membership` | Gruppe verlassen |
| `DELETE` | `/api/groups/{group_id}/members/{member_user_id}` | Mitglied entfernen |

### Wunschlisten

| Methode | Pfad | Beschreibung |
|---|---|---|
| `GET` | `/api/groups/{group_id}/wishlist` | Eigene Wunschliste abrufen |
| `POST` | `/api/groups/{group_id}/wishlist` | Wunsch hinzufügen |
| `PUT` | `/api/groups/{group_id}/wishlist/{item_id}` | Wunsch bearbeiten |
| `DELETE` | `/api/groups/{group_id}/wishlist/{item_id}` | Wunsch löschen |

### Auslosung

| Methode | Pfad | Beschreibung |
|---|---|---|
| `POST` | `/api/groups/{group_id}/draw` | Gruppe auslosen |
| `GET` | `/api/groups/{group_id}/assignment` | Eigene Zuweisung abrufen |

Das Backend stellt insgesamt 19 API-Operationen über 13 unterschiedliche Pfade bereit.

## API-Dokumentation

FastAPI erzeugt automatisch folgende Dokumentation:

- `/docs`
- `/redoc`
- `/openapi.json`

## Tests

Tests und Syntaxprüfung ausführen:

```bash
python -m pytest -q
python -m compileall -q app tests
```

Docker-Konfiguration und Image prüfen:

```bash
docker compose config
docker compose build
```

## Datensicherung

Vor einer Sicherung sollte eine konsistente SQLite-Kopie erzeugt werden:

```bash
docker exec -i wichtel-backend python3 - <<'PY'
import sqlite3

source = sqlite3.connect("/app/data/wichtel.db")
target = sqlite3.connect("/app/data/wichtel-backup.db")

with target:
    source.backup(target)

source.close()
target.close()
PY
```

Die erzeugte Datei anschliessend aus dem Datenverzeichnis kopieren und ausserhalb des Repositorys speichern.

## Sicherheit

Der Container und die Anwendung sind unter anderem wie folgt abgesichert:

- Betrieb ohne Root-Rechte
- schreibgeschütztes Root-Dateisystem
- Entfernung aller Linux-Capabilities
- `no-new-privileges`
- Schreibzugriff nur auf `/app/data` und `/tmp`
- Geräte-Token und Recovery-Keys nur als Hash
- Berechtigungsprüfungen für Benutzer, Gruppen und Wunschlisten
- Grenzwerte für Geräte, Gruppen, Mitglieder und Wünsche
- Rate Limits für Registrierung, Recovery und Gruppenbeitritt
- Auswertung weitergeleiteter Client-IP-Adressen nur über vertrauenswürdige Proxies

## Lizenz

Dieses Projekt steht unter der GNU Affero General Public License, Version 3 oder höher (`AGPL-3.0-or-later`).

Siehe die Datei `LICENSE` für den vollständigen Lizenztext.
