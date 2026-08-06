# Wichtel Backend

REST-Backend für die Android-App **Wichtel**. Die Anwendung ermöglicht das Erstellen von Wichtelgruppen, eine zufällige Auslosung sowie gruppenbezogene Wunschlisten.

Das Backend basiert auf FastAPI und SQLite und kann vollständig mit Docker Compose betrieben werden.

## Funktionen

- Benutzerkonto ohne E-Mail-Adresse oder externe Anmeldung
- Wiederherstellung über Account-Code und Recovery-Key
- Gerätebasierte Authentifizierung mit Bearer-Token
- Wichtelgruppen erstellen, bearbeiten und verlassen
- Gruppenbeitritt über Einladungscode
- Verwaltung von Gruppenmitgliedern
- Zufällige Auslosung ohne Selbstzuweisung
- Gruppenbezogene Wunschlisten
- Schutz bereits ausgeloster Gruppen vor nachträglichen Änderungen
- Rate Limiting für besonders sensible Endpunkte
- Automatische OpenAPI-Dokumentation
- SQLite-Datenbank ohne externe Datenbankdienste

## Technologie

- Python 3.12 oder neuer
- FastAPI
- Pydantic
- SQLite
- Uvicorn
- Docker und Docker Compose
- Pytest

## Projektstruktur

```text
app/
├── main.py                 FastAPI-Anwendung und Router-Einbindung
├── auth.py                 Authentifizierung über Geräte-Token
├── config.py               Umgebungsvariablen und Grenzwerte
├── database.py             Datenbankinitialisierung und Hilfsfunktionen
├── identifiers.py          Account-, Recovery- und Einladungscodes
├── rate_limit.py           Rate-Limiting und Client-IP-Ermittlung
├── schemas.py              Pydantic-Request- und Response-Modelle
├── security.py             Hashing sicherheitsrelevanter Werte
├── time_utils.py           UTC-Zeitfunktionen
├── validation.py           Eingabevalidierung
└── routers/
    ├── health.py           Health-Endpunkt
    ├── users.py            Registrierung und Benutzerkonto
    ├── groups.py           Gruppen und Mitgliedschaften
    ├── wishlists.py        Wunschlisten
    └── draw.py             Auslosung und Zuweisungen

tests/
└── test_api_security.py    API-, Berechtigungs- und Sicherheitstests
Installation mit Docker Compose

Repository klonen:

git clone https://github.com/michard8590/wichtel-backend.git
cd wichtel-backend

Container bauen und starten:

docker compose up -d --build

Status anzeigen:

docker compose ps

Logs verfolgen:

docker compose logs -f

Container stoppen:

docker compose down

Die SQLite-Datenbank wird im persistenten Datenverzeichnis des Containers gespeichert.

Lokale Entwicklung

Virtuelle Python-Umgebung erstellen:

python3 -m venv .venv
source .venv/bin/activate

Abhängigkeiten installieren:

pip install --requirement requirements.txt

Für einen lokalen Start muss ein beschreibbarer Datenbankpfad angegeben werden:

export DATABASE_PATH=/tmp/wichtel-development.db

Anwendung starten:

uvicorn app.main:app     --host 127.0.0.1     --port 8000     --reload
Konfiguration

Die Konfiguration erfolgt über Umgebungsvariablen.

Wichtige Variablen:

Variable	Beschreibung
DATABASE_PATH	Pfad zur SQLite-Datenbank
RATE_LIMIT_ENABLED	Aktiviert oder deaktiviert das Rate Limiting
TRUSTED_PROXY_NETWORKS	Vertrauenswürdige Proxy-Netzwerke für die Client-IP-Ermittlung
MAX_ACTIVE_DEVICES_PER_USER	Maximale Anzahl aktiver Geräte pro Benutzer
MAX_OPEN_GROUPS_PER_OWNER	Maximale Anzahl offener Gruppen pro Besitzer
MAX_GROUP_MEMBERS	Maximale Anzahl Mitglieder pro Gruppe
MAX_WISHLIST_ITEMS_PER_USER_GROUP	Maximale Anzahl Wünsche pro Benutzer und Gruppe

Für die produktive Umgebung sollten Konfigurationswerte über Docker Compose oder eine nicht eingecheckte .env-Datei gesetzt werden.

Authentifizierung

Geschützte Endpunkte erwarten ein Geräte-Token im HTTP-Header:

Authorization: Bearer DEVICE_TOKEN

Das Geräte-Token wird bei der Registrierung oder Wiederherstellung eines Kontos ausgegeben.

Sicherheitsrelevante Werte werden nicht im Klartext in der Datenbank gespeichert.

API-Endpunkte
System
Methode	Pfad	Beschreibung
GET	/api/health	Status des Backends
Benutzer
Methode	Pfad	Beschreibung
POST	/api/users/register	Benutzer registrieren
POST	/api/users/recover	Benutzerkonto wiederherstellen
PATCH	/api/users/me	Eigenes Profil bearbeiten
DELETE	/api/users/me	Eigenes Benutzerkonto löschen
Gruppen
Methode	Pfad	Beschreibung
GET	/api/groups	Eigene Gruppen auflisten
POST	/api/groups	Gruppe erstellen
POST	/api/groups/join	Einer Gruppe beitreten
GET	/api/groups/{group_id}	Gruppendetails abrufen
PATCH	/api/groups/{group_id}	Gruppe bearbeiten
DELETE	/api/groups/{group_id}	Gruppe löschen
DELETE	/api/groups/{group_id}/membership	Gruppe verlassen
DELETE	/api/groups/{group_id}/members/{member_user_id}	Mitglied entfernen
Wunschlisten
Methode	Pfad	Beschreibung
GET	/api/groups/{group_id}/wishlist	Eigene Wunschliste abrufen
POST	/api/groups/{group_id}/wishlist	Wunsch hinzufügen
PUT	/api/groups/{group_id}/wishlist/{item_id}	Wunsch bearbeiten
DELETE	/api/groups/{group_id}/wishlist/{item_id}	Wunsch löschen
Auslosung
Methode	Pfad	Beschreibung
POST	/api/groups/{group_id}/draw	Gruppe auslosen
GET	/api/groups/{group_id}/assignment	Eigene Zuweisung abrufen

Insgesamt stellt das Backend 19 API-Operationen über 13 unterschiedliche Pfade bereit.

API-Dokumentation

FastAPI erzeugt die Dokumentation automatisch:

/docs
/redoc
/openapi.json

Die Dokumentation ist verfügbar, sobald das Backend läuft.

Tests

Alle Tests ausführen:

python -m pytest -q

Syntax aller Python-Dateien prüfen:

python -m compileall -q app tests

Docker-Konfiguration prüfen:

docker compose config

Docker-Image bauen:

docker compose build

Aktueller Testumfang:

Authentifizierung und Berechtigungen
Benutzerregistrierung und Wiederherstellung
Gruppenmitgliedschaften
Schutz vor unerlaubten Gruppenänderungen
Auslosung ohne Selbstzuweisung
Zugriff auf Zuweisungen
Validierung von Wunschlisten-Links
Löschung von Konten und Gruppen
konfigurierbare Grenzwerte
Rate Limiting
Sicherheit

Das Backend enthält unter anderem folgende Schutzmechanismen:

Geräte-Token werden nur gehasht gespeichert.
Recovery-Keys werden nur gehasht gespeichert.
Benutzer können nur auf ihre eigenen beziehungsweise freigegebenen Daten zugreifen.
Nur der Gruppenbesitzer darf administrative Gruppenaktionen ausführen.
Eine Auslosung kann nur durch den Gruppenbesitzer gestartet werden.
Nach erfolgter Auslosung werden kritische Gruppenänderungen blockiert.
Wunschlisten akzeptieren nur gültige HTTP- und HTTPS-Links.
Sensible Endpunkte können durch Rate Limiting geschützt werden.
Weitergeleitete Client-IP-Adressen werden nur von konfigurierten vertrauenswürdigen Proxies akzeptiert.
Lizenz

Dieses Projekt steht unter der GNU Affero General Public License, Version 3 oder höher:

AGPL-3.0-or-later

Siehe die Datei LICENSE für den vollständigen Lizenztext.
