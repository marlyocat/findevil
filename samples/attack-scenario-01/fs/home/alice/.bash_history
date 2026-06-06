ls
cd /var/log
tail -n 100 nginx/access.log
tail -n 100 nginx/error.log
sudo systemctl status nginx
sudo systemctl restart nginx
journalctl -u nginx -f
exit
