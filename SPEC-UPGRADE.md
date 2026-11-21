# Spec: upgrade di izdock/server-manager

Verifica delle versioni del 21/11/2026 e piano di upgrade. Si spunta una casella quando il punto è
fatto **e** verificato (build verde, verifica dell'immagine OK, test della Fase 4 dove richiesto).

Riferimenti:
- versioni e checksum dei componenti: [versions.env](versions.env), unica fonte di verità (SSOT)
- logica di build: [build/install.sh](build/install.sh)
- CI: [.gitea/workflows/build.yml](.gitea/workflows/build.yml), [.gitea/workflows/publish.yml](.gitea/workflows/publish.yml), [.gitea/workflows/updates.yml](.gitea/workflows/updates.yml)
- controlli sull'immagine: [verify-image.sh](.gitea/actions/build-push/verify-image.sh) (dentro l'immagine) e [smoke-test.sh](.gitea/actions/build-push/smoke-test.sh) (container avviato con l'entrypoint)

## Stato rilevato (21/11/2026)

| Componente | Prima (1.14.2) | Ora (2.0.0) | Note |
|---|---|---|---|
| Debian (base) | 11 bullseye | 13.8 trixie, fissata per digest | bullseye fuori supporto; i suoi pacchetti sono passati su `archive.debian.org` (404 sul mirror: la build 1.x non funzionava più) |
| PHP (Debian) | 7.4 | 8.4 | |
| Node.js | 20 | 24 LTS | esiste anche la 26 LTS (vedi decisioni) |
| Cronicle | 0.9.76 | 0.9.147 | dalla 0.9.129 richiede Node >= 22.12 |
| MySQL client | 8.0 (`mysql-apt-config` 0.8.22) | 8.4 LTS (`mysql-apt-config` 0.8.36) | |
| Repo PostgreSQL | bullseye-pgdg (404) | trixie-pgdg | |
| Zabbix agent2 | 7.0, pacchetto `+debian10` | 7.0.32 LTS, pacchetto `7.0-5+debian13` | c'è anche la 8.0 |
| gcsfuse | 2.10.0 dichiarata, non applicata | 3.13.1 fissata | |
| phpMyAdmin | 5.2.2 | 5.2.3 | upstream la dichiara per PHP < 8.4 |
| Adminer | 5.0.4 | 6.3.1 | |
| synbak | 3.8.5 | 3.8.5 | |
| izmysqlsync, izmysqlrestore, mysqltuner | da `master` | tag / commit fissati con sha256 | |

## Fase 0 — CI: da Drone a Gitea Actions

- [x] Eliminata la pipeline Drone (`.drone.yml`)
- [x] `versions.env` come SSOT: `APP_VER` (versione dell'immagine, prima era il tag git), immagine base e versioni dei componenti con sha256, letti da Dockerfile, `tools/build.sh` e CI
- [x] `build/lib.sh` (`load_versions`, `base_image`, `download` con verifica sha256): lo stesso codice nella build, in locale e in CI
- [x] `tools/build.sh`: build locale con gli stessi build-arg della CI (`DOCKER=podman` supportato)
- [x] Workflow `server-manager-build`: lint, build, push sul registry Gitea, verifica e smoke test; poi publish automatico (disattivabile con la casella quando lo si lancia a mano). Sulle pull request fa solo build e verifica, senza pubblicare
- [x] Workflow `server-manager-publish`: publish manuale con un click (default: l'ultima build, `latest`, push su GitHub)
- [x] Logica di publish in un solo posto (`.gitea/actions/publish`): copia su Docker Hub per digest, gitleaks, push fast-forward su GitHub del commit da cui è stata costruita l'immagine
- [x] Tag git `APP_VER` (es. `2.0.0`) creato dal publish sul commit dell'immagine, su GitHub e sul Gitea, mai spostato (con Drone lo creava a mano chi rilasciava); `2.0.0` creato su `9cdccbe` dalla run #2 di `server-manager-publish`
- [x] Action condivise copiate da izdock/tomcat (stesso codice): `registry-login`, `image-tags`, `promote`, `gitleaks`, `dockerhub-readme`, `matrix-notify`
- [x] Rebuild settimanale (lunedì) con `OS_UPDATE_STAMP` per gli aggiornamenti di sicurezza del sistema operativo
- [x] Hook locale `.githooks/pre-commit` (lint + gitleaks) e `.gitleaks.toml`
- [x] README aggiornato: tag supportati, base trixie, build con `tools/build.sh`, note di upgrade da 1.x
- [x] Branch principale rinominato da `master` a `main`: in locale, sul Gitea e su GitHub (branch predefinito `main` su entrambi), e nei workflow
- [x] Remote `origin` sul nuovo Gitea dell'organizzazione `initzero` e remote `github` in sola lettura (push disattivato): niente push manuali su GitHub, ci pensa la CI
- [x] Repository `izdock-server-manager` presente sul Gitea dell'organizzazione `initzero`
- [x] Actions abilitate sul repository Gitea
- [x] GitHub aveva un branch spurio chiamato `HEAD`: un residuo del 17/11/2021 (commit `0c7dfbb`, «synbak 3.8.3»), già contenuto in `main`; cancellato il 21/11/2026
- [x] `GH_PUSH_TOKEN` dell'organizzazione può scrivere su `ugoviti/izdock-server-manager` (run #1: commit `9cdccbe` pushato su GitHub `main`)
- [x] `PACKAGES_USERNAME` scrive i pacchetti di `initzero` (run #1: immagine e cache sul registry Gitea)
- [x] Descrizione su Docker Hub aggiornata dal README con `DOCKER_PASSWORD`: `DOCKERHUB_README_TOKEN` non serve
- [ ] (opzionale) `GITLEAKS_CONFIG` con le regole private, come negli altri repo izdock
- [ ] (opzionale) `UPDATES_TOKEN`: senza, le PR settimanali aperte con il token automatico potrebbero non avviare la build di controllo
- [x] Primo run verde di `server-manager-build` (run #1 del 21/11/2026): lint, build, 74 controlli OK tra verifica e smoke test, gitleaks, notifiche Matrix inviate, tag `2.0.0`, `2.0`, `2`, `2.0.0-1` e `latest` su Docker Hub (`1`, `1.14` restano sulla 1.14.2)
- [x] Hook locale abilitato nel clone (`git config core.hooksPath .githooks`)

- [x] 2.0.1: `izcertbot` vedeva un CN sbagliato su ogni certificato con OpenSSL 3 (`subject=CN=x` invece di `CN = x`):
  a ogni avvio spostava in backup e richiedeva di nuovo i certificati validi (19 al primo avvio in produzione,
  rischio di rate limit Let's Encrypt). Ora legge il CN in formato RFC2253 e accetta il dominio principale anche
  tra i SAN; `verify-image.sh` lo controlla

## Fase 1 — Hotfix su bullseye

Non necessaria: si è passati direttamente alla Fase 2. Serviva solo per avere un'immagine bullseye
prima della migrazione (sorgenti apt su `archive.debian.org`, pgdg su `apt-archive.postgresql.org`,
pacchetto Zabbix `7.0-5+debian11`).

## Fase 2 — Migrazione a Debian 13 trixie

Base e repository:
- [x] `debian:trixie-slim` fissata per digest (`DEBIAN_CODENAME`, `DEBIAN_DIGEST` in `versions.env`); la build si ferma se la release non corrisponde
- [x] Tolto `software-properties-common` (non esiste in trixie)
- [x] Niente più `apt-key`: chiavi in `/etc/apt/keyrings` con `signed-by=` per pgdg, gcsfuse e NodeSource; MySQL e Zabbix installano il proprio keyring
- [x] Repo PostgreSQL `trixie-pgdg`
- [x] NodeSource configurato direttamente (niente più `curl setup_XX.x | bash`)

Componenti (`versions.env`):
- [x] `NODEJS_VERSION=24` (verificato: node 24.22.3)
- [x] `CRONICLE_VERSION=0.9.147`
- [x] MySQL 8.4 LTS: `MYSQL_APT_CONFIG_VERSION=0.8.36-1`, `MYSQL_SERIES=8.4-lts` (verificato: client 8.4.13)
- [x] Zabbix `ZABBIX_RELEASE=7.0-5` per debian13 (verificato: agent2 7.0.32)
- [x] gcsfuse fissato davvero (`gcsfuse=${GCSFUSE_VERSION}`), 3.13.1
- [x] `ADMINER_VERSION=6.3.1`, `PMA_VERSION=5.2.3`
- [x] `p7zip` → `7zip`; aggiunto `iproute2` (l'entrypoint usa `ip route` per `FTP_PASV_ADDR`)

Script:
- [x] `PHP_CONF` ricavato dal PHP installato (`/etc/php/*/apache2/php.ini`); la verifica dell'immagine fallisce se torna una versione fissa
- [x] proftpd 1.3.8c: caricati `mod_ls` e `mod_xfer` (in Debian 13 sono moduli DSO) e tolto `mod_wrap` (non esiste più); trovato dallo smoke test
- [x] `verify-image.sh` aggiornato: release Debian, versioni di Node, Cronicle, MySQL, gcsfuse, Zabbix, phpMyAdmin, Adminer, moduli PHP, `apache2ctl -t`

## Fase 3 — Pulizia e riproducibilità

- [x] Tolti gli `.ini` di supervisor dei servizi mai installati (`vsftpd`, `socklog`, `proxy`)
- [x] `postfix.ini` resta (lo usa `chkService`), ma con `POSTFIX_ENABLED=true` e postfix non installato l'entrypoint avvisa e non lo avvia (l'MTA è dma)
- [x] `proxy.ini` con l'host di test fisso eliminato
- [x] izmysqlsync (tag 2.0.4), izmysqlrestore (commit fissato: il repo non ha tag) e mysqltuner (tag 2.9.4) con sha256 in `versions.env`, scaricati in https
- [x] synbak: le release upstream non pubblicano pacchetti, resta il `.deb` in `files/`
- [x] Dockerfile: `ENV KEY=value`, `COPY` al posto di `ADD`, `apt-get`, pacchetti duplicati tolti, hadolint pulito
- [x] Logica d'installazione in `build/install.sh`, controllata da shellcheck
- [x] `tools/lint.sh` (shellcheck + hadolint con versioni fissate) come primo passo di `server-manager-build`
- [x] `tools/make-updates.sh` (report e `--apply`, resta sulla stessa versione principale) e workflow settimanale `server-manager-updates` che apre una PR con `versions.env` aggiornato
- [x] Lint di `rootfs/` (entrypoint e script in `/usr/local/sbin`) in `tools/lint.sh`: corretti due bug (`izcertbot` non impostava mai l'email predefinita; `chown` su una variabile mai definita) e gli avvisi di quoting; le divisioni in parole volute sono eccezioni motivate
- [x] Cronicle: su un volume dati nuovo la password di `admin` è `CRONICLE_ADMIN_PASSWORD` o una casuale stampata nel log (non più `admin`/`admin`); la variabile non arriva al processo di Cronicle; i volumi esistenti tengono le loro password

## Fase 4 — Test prima del rilascio della versione trixie

Fatti in locale con podman sull'immagine 2.0.0 (21/11/2026):
- [x] Cronicle: volume `data` creato con la 1.14.2 (Node 20, Cronicle 0.9.76) riaperto dalla 2.0.0: login admin, evento esistente presente, job eseguito con esito 0
- [x] SSH: chiave host RSA (PEM) generata dalla 1.14.2 riusata dalla 2.0.0, servita sia da sshd (2222, OpenSSH 10) sia dall'SFTP di proftpd (22); login root con password
- [x] FTP con login e upload, FTPS esplicito (AUTH TLS) e implicito (990), SFTP con proftpd 1.3.8c
- [x] Apache con PHP 8.4: phpMyAdmin 5.2.3 e Adminer 6.3.1 rispondono (HTTP 200), `sendmail_path` di php.ini impostato su `izsendmail`
- [x] `mail()` di PHP accettato da `izsendmail`/dma
- [x] client MySQL 8.4 (`mysql`, `mysqldump`) e `mysqli` di PHP verso MySQL 8.4 e MariaDB 10.11
- [x] Zabbix agent2 e NRPE si avviano da supervisor
- [x] Import di utenti e gruppi da CSV (uid, gruppi, home, shell), login FTP e SSH degli utenti importati
- [x] Nessun programma di supervisor in FATAL con la configurazione predefinita; lo stop del container avviene in pochi secondi

Da fare con l'ambiente reale:
- [ ] Login di phpMyAdmin verso i database reali (avvisi di PHP 8.4)
- [ ] Consegna effettiva delle mail tramite il relay configurato in `MTA_*`
- [ ] `mysqldump`, `izmysqlsync` e `izmysqlrestore` verso i server reali (in particolare eventuali MySQL 5.7)
- [ ] Mount gcsfuse 3.x dentro il container (richiede credenziali e `/dev/fuse`)
- [ ] certbot 4.0 (`izcertbot`) e OpenVPN con le configurazioni reali
- [x] Bump di versione principale: `APP_VER=2.0.0` (base nuova; i dati di Cronicle aggiornati non tornano indietro)

## Decisioni

- [x] phpMyAdmin con PHP 8.4: scelta (a), provarlo così com'è; funziona nello smoke test, resta da provare il login verso i database reali. Alternative: PHP 8.3 dal repo sury, o bookworm (PHP 8.2)
- [x] Zabbix: resta sulla 7.0 LTS (`tools/make-updates.sh` segnala la 8.0)
- [x] Node.js 24 LTS (supporto fino ad aprile 2028). È uscita anche la 26 LTS: valutarla quando Cronicle la dichiara supportata
