#!/bin/sh

sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
sed -i 's/#MaxSessions 10/MaxSessions 10/' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 1m/' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#MaxStartups 10:30:100/MaxStartups 10:30:60/' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config
sed -i '27 i KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' /etc/ssh/sshd_config
sed -i '28 i Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' /etc/ssh/sshd_config
sed -i '29 i MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' /etc/ssh/sshd_config
systemctl restart sshd

echo -e -n "\e[0;33mWhich user account password do you want to delete?\033[0m "
read account
passwd -d $account

echo -e -n "\e[0;33mWhich user account password do you want to delete?\033[0m "
read account
passwd -d $account