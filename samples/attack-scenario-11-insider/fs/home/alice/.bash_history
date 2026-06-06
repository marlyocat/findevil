cd /var/log
grep -i error nginx/error.log | tail -50
tail -f mysql/error.log
ls -la
mysql -u root -p -e 'SHOW PROCESSLIST'
htop
logout
cd ~
sudo systemctl status mysql
logout
cd /tmp
sudo mysqldump --all-databases --single-transaction > dump-20260415.sql
sudo gzip dump-20260415.sql
sudo chmod 644 dump-20260415.sql.gz
sudo chown alice:alice dump-20260415.sql.gz
ls -la dump-20260415.sql.gz
scp -i ~/.ssh/personal_ed25519 dump-20260415.sql.gz alice@home.malan-personal.net:/srv/backup/corp-db/
rm dump-20260415.sql.gz
history -c
