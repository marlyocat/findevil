apt update
apt upgrade
systemctl restart nginx
tail -f /var/log/nginx/error.log
