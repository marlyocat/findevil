ls
cd /var/log
tail -n 100 nginx/access.log
sudo journalctl -u nginx --since '1 hour ago'
sudo systemctl status nginx
exit
