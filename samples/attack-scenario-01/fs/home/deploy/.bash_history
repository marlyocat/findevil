git pull origin main
npm ci
npm run build
npm test
git status
git log --oneline -5
systemctl status nginx
journalctl -u nginx --since 10min
git push origin deploy-branch
docker ps
docker logs web
ls -la
exit
