ls -la
cd /var/backups/db
ls -la
sudo mysqldump --single-transaction customers_v2 > /var/backups/db/customers_v2-20260422.sql
sudo gzip /var/backups/db/customers_v2-20260422.sql
sudo chmod 640 /var/backups/db/customers_v2-20260422.sql.gz
sudo aws s3 cp /var/backups/db/customers_v2-20260422.sql.gz s3://corp-db-backups/daily/
ls -la
df -h /var
logout
