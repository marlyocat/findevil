last -n 20
sudo last -n 20
sudo tail -n 200 /var/log/auth.log
grep -i 'Accepted password' /var/log/auth.log
sudo systemctl status auditd
sudo systemctl start auditd
sudo lsattr /tmp/.x
sudo chattr -i /tmp/.x
sudo rm /tmp/.x
sudo userdel -r sysd
sudo grep sysd /etc/passwd
sudo passwd root
sudo vi /etc/ssh/sshd_config
sudo systemctl restart sshd
sudo iptables -I INPUT -s 45.123.45.67 -j DROP
sudo iptables -L INPUT -n | head
sudo mkdir -p /root/incident-response
sudo cp /etc/shadow /root/incident-response/shadow.snapshot.txt
sudo tar -czf /root/incident-response/artifact-bundle.tar.gz /etc /var/log
ls -la /root/incident-response/
# paging on-call sec-eng, logging out to preserve state
logout
