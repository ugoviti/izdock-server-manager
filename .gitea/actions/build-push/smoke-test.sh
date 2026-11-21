#!/bin/bash
# smoke-test.sh IMAGE: start the image with its real entrypoint (Cronicle enabled, no CSV import)
# and check that the services run and answer. Run on the docker host, after verify-image.sh.
#   .gitea/actions/build-push/smoke-test.sh izdock/server-manager:local
# Prints one OK/FAIL line per check, exit 1 if any check fails. DOCKER=podman to use podman.
set -u
image=${1:?usage: smoke-test.sh IMAGE}
docker=${DOCKER:-docker}
name="server-manager-smoke-$$"
FAIL=0
ok() { echo "OK   $*"; }
ko() { echo "FAIL $*"; FAIL=1; }
inside() { "$docker" exec "$name" bash -c "$1" >/dev/null 2>&1; }
# wait_for SECONDS DESCRIPTION COMMAND: retry the command inside the container
wait_for() {
  local t=$1 what=$2 cmd=$3 i
  for ((i = 0; i < t; i++)); do inside "$cmd" && { ok "$what"; return; }; sleep 1; done
  ko "$what (after ${t}s)"
}
cleanup() { "$docker" rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$docker" run -d --name "$name" -e CSV_IMPORT=false -e CRONICLE_ENABLED=true -e ROOT_PASSWORD=smoke-test "$image" >/dev/null ||
  { echo "FAIL container does not start"; exit 1; }

wait_for 60 "supervisord running" "pgrep -x supervisord"
for p in sshd proftpd apache2 rsyslogd cron; do
  wait_for 30 "$p running" "pgrep -x $p"
done
wait_for 30 "ssh port 2222" "echo > /dev/tcp/127.0.0.1/2222"
wait_for 30 "ftp port 21" "echo > /dev/tcp/127.0.0.1/21"
wait_for 30 "sftp port 22 (proftpd)" "echo > /dev/tcp/127.0.0.1/22"
wait_for 30 "phpMyAdmin answers (http 200)" "curl -fsS -o /dev/null http://127.0.0.1/admin/pma/"
wait_for 30 "Adminer answers (http 200)" "curl -fsS -o /dev/null http://127.0.0.1/admin/adminer/"
wait_for 90 "Cronicle answers on port 3012" "curl -fsS -o /dev/null http://127.0.0.1:3012/"
# logins: root over ssh, a local user over ftp (list + upload) and over sftp (proftpd)
inside "useradd -m -s /bin/bash smoke && echo 'smoke:Sm0ke-test' | chpasswd && echo hello > /tmp/smoke.txt"
wait_for 10 "ssh login as root (port 2222)" "sshpass -p smoke-test ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 true"
wait_for 10 "ftp login and upload" "curl -fsS -T /tmp/smoke.txt ftp://smoke:Sm0ke-test@127.0.0.1/smoke.txt && curl -fsS ftp://smoke:Sm0ke-test@127.0.0.1/ | grep -q smoke.txt"
wait_for 10 "sftp login (proftpd port 22)" "curl -fsS -k sftp://smoke:Sm0ke-test@127.0.0.1:22/~/smoke.txt | grep -q hello"
# php.ini of the installed PHP edited by the entrypoint (izsendmail)
wait_for 10 "php.ini sendmail_path is izsendmail" "php -c \$(ls /etc/php/*/apache2/php.ini) -r 'exit(strpos(ini_get(\"sendmail_path\"), \"izsendmail\") === false ? 1 : 0);'"

state=$("$docker" exec "$name" supervisorctl -c /etc/supervisor/supervisord.conf status 2>/dev/null)
if grep -qE 'FATAL|BACKOFF|EXITED' <<< "$state"; then ko "supervisor programs: $(grep -E 'FATAL|BACKOFF|EXITED' <<< "$state" | tr -s ' ' | paste -sd';' -)"; else ok "no supervisor program in FATAL/BACKOFF/EXITED"; fi

if [ "$FAIL" -ne 0 ]; then
  echo "---------- container log (last 60 lines)"
  "$docker" logs --tail 60 "$name" 2>&1
fi
exit $FAIL
