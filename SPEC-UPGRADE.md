# Spec: upgrade di izdock/server-manager

Verifica delle versioni del 21/11/2026 e piano di upgrade. Si spunta una casella quando il punto è
fatto **e** verificato (build verde, verifica dell'immagine OK, test della Fase 4 dove richiesto).

Riferimenti:
- versioni dei componenti: [versions.env](versions.env), unica fonte di verità (SSOT)
- CI: [.gitea/workflows/build.yml](.gitea/workflows/build.yml) e [.gitea/workflows/publish.yml](.gitea/workflows/publish.yml)
- controlli automatici sull'immagine: [.gitea/actions/build-push/verify-image.sh](.gitea/actions/build-push/verify-image.sh)

## Stato rilevato (21/11/2026)

| Componente | Nel progetto | Ultima / supportata | Stato |
|---|---|---|---|
| Debian (base) | 11 bullseye | 13.8 trixie | fuori supporto: `bullseye-security` è fermo al 12/09/2026 e i suoi pacchetti sono passati su `archive.debian.org` (404 sul mirror: la build si rompe) |
| PHP (Debian) | 7.4 | 8.4 (trixie), 8.2 (bookworm) | fuori supporto upstream dal 2022 |
| Node.js | 20 | 24 LTS (fino ad apr 2028), 22 LTS | fuori supporto; repo NodeSource fermo al 30/04/2026 |
| Cronicle | 0.9.76 | 0.9.147 | dalla 0.9.129 richiede Node >= 22.12; molte correzioni di vulnerabilità |
| MySQL client | 8.0 (`mysql-apt-config` 0.8.22) | 8.4 LTS (`mysql-apt-config` 0.8.36) | 8.0 fuori supporto da apr 2026 |
| Repo PostgreSQL | `apt.postgresql.org` bullseye-pgdg | spostato su `apt-archive.postgresql.org` | risponde 404: la build si rompe |
| Zabbix agent2 | 7.0, pacchetto `+debian10` | 7.0.32 LTS (`zabbix-release_latest_7.0+debian13`) | pacchetto per Debian 10 su Debian 11; c'è anche la 8.0 |
| gcsfuse | `GCSFUSE_VERSION` 2.10.0 | 3.13.1 | la variabile non è usata: apt installa sempre l'ultima |
| phpMyAdmin | 5.2.2 | 5.2.3 | supporta solo PHP < 8.4 |
| Adminer | 5.0.4 | 6.3.1 | nuova versione principale |
| synbak | 3.8.5 | 3.8.5 | aggiornato |
| izmysqlsync, izmysqlrestore, mysqltuner | presi da `master` | — | versione non fissata, nessun checksum |

## Fase 0 — CI: da Drone a Gitea Actions

- [x] Eliminata la pipeline Drone (`.drone.yml`)
- [x] `versions.env` come SSOT: `APP_VER` (versione dell'immagine, prima era il tag git) e versioni dei componenti, letti da Dockerfile, `tools/build.sh` e CI
- [x] `build/lib.sh` (`load_versions`), lo stesso codice nella build dell'immagine, in locale e in CI
- [x] `tools/build.sh`: build locale con gli stessi build-arg della CI (`DOCKER=podman` supportato)
- [x] Workflow `server-manager-build`: build, push sul registry Gitea, verifica dell'immagine; poi publish automatico (disattivabile con la casella quando lo si lancia a mano)
- [x] Workflow `server-manager-publish`: publish manuale con un click (default: l'ultima build, `latest`, push su GitHub)
- [x] Logica di publish in un solo posto (`.gitea/actions/publish`): copia su Docker Hub per digest, gitleaks, push fast-forward su GitHub del commit da cui è stata costruita l'immagine
- [x] Action condivise copiate da izdock/tomcat (stesso codice): `registry-login`, `image-tags`, `promote`, `gitleaks`, `dockerhub-readme`, `matrix-notify`
- [x] Rebuild settimanale (lunedì) con `OS_UPDATE_STAMP` per gli aggiornamenti di sicurezza del sistema operativo
- [x] Hook locale `.githooks/pre-commit` (gitleaks) e `.gitleaks.toml`
- [ ] Remote `origin` sul nuovo Gitea dell'organizzazione `initzero` (oggi punta all'istanza vecchia) e remote `github` in sola lettura: niente push manuali su GitHub, ci pensa la CI
- [ ] Repository `izdock-server-manager` presente sul Gitea dell'organizzazione `initzero`, con Actions abilitate
- [ ] Verificare che `GH_PUSH_TOKEN` dell'organizzazione abbia Contents: Read and write anche su `ugoviti/izdock-server-manager`; se non lo ha, creare un secret di repository con lo stesso nome
- [ ] Verificare che `PACKAGES_USERNAME` possa scrivere i pacchetti di `initzero` (team con Packages: Write)
- [ ] (opzionale) `DOCKERHUB_README_TOKEN` (Read, Write, Delete) per aggiornare la descrizione su Docker Hub; senza, si prova con `DOCKER_PASSWORD`
- [ ] (opzionale) `GITLEAKS_CONFIG` con le regole private, come negli altri repo izdock
- [ ] Primo run verde di `server-manager-build` (possibile solo dopo la Fase 1 o la Fase 2), notifica Matrix ricevuta, tag `X.Y.Z`, `X.Y`, `X`, `X.Y.Z-<run>` e `latest` su Docker Hub
- [ ] Aggiornare il README: sezione build (`tools/build.sh`) e tag supportati (oggi dice 1.12, buster, PHP 7.3)

## Fase 1 — Hotfix su bullseye (per avere subito una build funzionante)

Oggi la build si rompe già al primo `apt install`: i pacchetti di `bullseye-security` sono stati
spostati su `archive.debian.org` e rispondono 404 su `deb.debian.org` (build locale del 21/11/2026,
`exit status 100`). Il hotfix serve solo se occorre un'immagine bullseye prima della Fase 2; altrimenti
conviene passare direttamente alla Fase 2.

- [ ] Sorgenti apt di Debian su `archive.debian.org` (`bullseye`, `bullseye-updates`, `bullseye-security`), con `Check-Valid-Until=false`
- [ ] Repo PostgreSQL: `https://apt-archive.postgresql.org/pub/repos/apt bullseye-pgdg main`
- [ ] Zabbix: pacchetto `zabbix-release_7.0-5+debian11_all.deb` invece di `7.0-1+debian10`
- [ ] Bump di `APP_VER` in `versions.env` e build verde: soluzione temporanea, la base resta fuori supporto

## Fase 2 — Migrazione a Debian 13 trixie

Base e repository:
- [ ] `FROM debian:trixie-slim` (meglio fissata per digest, come izdock/tomcat)
- [ ] Togliere `software-properties-common` (non esiste in trixie; `add-apt-repository` non è usato)
- [ ] Sostituire `apt-key` (non c'è più in trixie) con chiavi in `/etc/apt/keyrings` e `signed-by=` per pgdg, gcsfuse, MySQL, Zabbix, NodeSource
- [ ] Repo PostgreSQL `trixie-pgdg` (client 17 da Debian, o la versione voluta da pgdg)

Componenti (`versions.env`):
- [ ] `NODEJS_VERSION=24`
- [ ] `CRONICLE_VERSION=0.9.147` (richiede Node >= 22.12)
- [ ] MySQL 8.4 LTS: `mysql-apt-config` 0.8.36 con `mysql-8.4-lts`; portare la versione del pacchetto in `versions.env`
- [ ] Zabbix `zabbix-release_latest_7.0+debian13_all.deb` (valutare la 8.0 in seguito)
- [ ] gcsfuse fissato davvero (`apt-get install gcsfuse=${GCSFUSE_VERSION}`), `GCSFUSE_VERSION=3.13.1`
- [ ] `ADMINER_VERSION=6.3.1`
- [ ] `PMA_VERSION=5.2.3`
- [ ] `p7zip` → `7zip` (in trixie `p7zip` è solo un pacchetto di transizione)

Script:
- [ ] `PHP_CONF` in `rootfs/entrypoint-hooks.sh` ricavato in automatico (`/etc/php/*/apache2/php.ini`) invece di `/etc/php/7.4/...` fisso: altrimenti i `sed` su `sendmail_path` e `auto_prepend_file` non hanno effetto e non danno errore (la verifica dell'immagine lo segnala)
- [ ] Aggiornare `verify-image.sh` se cambiano percorsi o moduli PHP

## Fase 3 — Pulizia e riproducibilità

- [ ] Togliere da supervisor gli `.ini` dei servizi non installati (`vsftpd`, `socklog`, `proxy`, `postfix`), oppure installare i programmi
- [ ] `proxy.ini`: togliere l'host di test fisso; se il proxy serve, renderlo configurabile da variabile d'ambiente
- [ ] izmysqlsync e izmysqlrestore da tag con sha256 in `versions.env` (come izdock/tomcat), non da `master`
- [ ] mysqltuner da una release fissa con sha256, scaricata in https
- [ ] synbak: valutare il download della release invece del `.deb` dentro il repo
- [ ] Dockerfile: `ENV KEY=value` al posto di `ENV KEY value`, `COPY` al posto di `ADD`, `apt-get` al posto di `apt`, togliere i pacchetti duplicati (`php-json`, `php-mbstring`, `proftpd-mod-msg`)
- [ ] Spostare la logica d'installazione in `build/install.sh` (come izdock/tomcat) per poterla controllare con shellcheck
- [ ] `tools/lint.sh` (shellcheck + hadolint con versioni fissate) e workflow di lint, come izdock/tomcat
- [ ] `tools/make-updates.sh` e workflow settimanale che apre una PR con `versions.env` aggiornato, come izdock/tomcat

## Fase 4 — Test prima del rilascio della versione trixie

- [ ] Backup del volume `/usr/local/cronicle/data`; con Cronicle 0.9.147 su Node 24 funzionano UI, login e job esistenti
- [ ] SSH con le chiavi host esistenti (OpenSSH da 8.4 a 10.0); le chiavi RSA in formato PEM restano leggibili dall'SFTP di proftpd
- [ ] FTP, FTPS e SFTP con proftpd 1.3.8c (moduli `mod_*` caricati, utenti creati dai CSV)
- [ ] Apache con PHP 8.4: phpMyAdmin 5.2.3 (supporta ufficialmente solo PHP < 8.4) e Adminer 6.3.1 funzionano
- [ ] Invio mail da PHP tramite `izsendmail` e `dma`
- [ ] `mysqldump`, `izmysqlsync` e `izmysqlrestore` con il client 8.4 verso i server reali (autenticazione, opzioni)
- [ ] Mount gcsfuse 3.x (fuse3) dentro il container
- [ ] certbot 4.0 (`izcertbot`), OpenVPN, NRPE e Zabbix agent2 si avviano da supervisor
- [ ] Bump di versione principale (`APP_VER=2.0.0`): l'immagine cambia base e i dati di Cronicle non tornano indietro

## Decisioni aperte

- [ ] phpMyAdmin con PHP 8.4: (a) provarlo comunque, (b) PHP 8.3 dal repo sury su trixie, (c) restare su bookworm (PHP 8.2, LTS fino a giugno 2028). Consiglio: (a), verificandolo nella Fase 4
- [ ] Zabbix 7.0 LTS o 8.0
- [ ] Node 24 (consigliato, LTS più lunga) o 22
