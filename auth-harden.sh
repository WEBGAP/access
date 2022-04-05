#!/bin/bash

#checks to see if the script was run as root
if [ $(id -u) != 0 ]; then
    echo "$(tput setaf 3)This script must be run as root.$(tput setaf 9)" 
    exit 1
fi

#gets the operating system NAME and saves as the variable osrelease
osrelease=$(awk -F= '$1=="NAME" { print $2 ;}' /etc/os-release)

#if the operating system ID isn't rocky nor centos the script exits after displaying a message
if [ "$osrelease" != '"Rocky Linux"' ] && [ "$osrelease" != '"CentOS Linux"' ] && [ "$osrelease" != '"Ubuntu"' ]; then
    echo "$(tput setaf 3)Please install on CentOS 7, Rocky 8, or Ubuntu 20.04 or newer. You are trying to install on $(tput bold)$osrelease.$(tput setaf 9)"

    sleep 2
    exit 1
fi

if [ "$osrelease" == '"Ubuntu"' ]; then

    #avoids ssh server config file replacement after changes below
    apt update; apt -y upgrade

    #creates users and home directories
    useradd --create-home -g sudo ryan; useradd --create-home -g sudo jun

    mkdir /home/ryan/.ssh && sudo chown ryan /home/ryan/.ssh && sudo chmod 700 /home/ryan/.ssh && sudo touch /home/ryan/.ssh/authorized_keys && sudo chown ryan /home/ryan/.ssh/authorized_keys && sudo chmod 600 /home/ryan/.ssh/authorized_keys && sudo echo 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMx78nvqVe1nnln04c9KCZM0gtV5xTyxrtvFkoxL/NA9hTC9zUYNC4Tw/WDHV0JY0gmunvNvEEfjEjkRsjaL4xs= ryan@webgap.io' >> /home/ryan/.ssh/authorized_keys
    mkdir /home/jun/.ssh && sudo chown jun /home/jun/.ssh && sudo chmod 700 /home/jun/.ssh && sudo touch /home/jun/.ssh/authorized_keys && sudo chown jun /home/jun/.ssh/authorized_keys && sudo chmod 600 /home/jun/.ssh/authorized_keys && sudo echo 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOitLpmSRgHqeucnSFCJLoEnSJVZzBBAxnRJ6nXqWBouctAKNK85y2pC98zJVMUVgC292vlOSF6RBUbGkmrjaGg= jun@webgap.io' >> /home/jun/.ssh/authorized_keys

    #hardens the ssh server
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

    #allows passwordless sudo
    sed -i '27 i %sudo ALL=(ALL:ALL) NOPASSWD:ALL' /etc/sudoers

    #requires password for su of all accounts except root
    sed -i '$ a auth        sufficient    pam_unix.so try_first_pass/' /etc/pam.d/su
    sed -i '$ a password    sufficient    pam_unix.so try_first_pass use_authtok sha512 shadow/' /etc/pam.d/su

    #deletes the root password
    passwd -d root

else

    #add user accounts and public keys
    useradd -g wheel ryan; useradd -g wheel jun

    mkdir /home/ryan/.ssh && sudo chown ryan /home/ryan/.ssh && sudo chmod 700 /home/ryan/.ssh && sudo touch /home/ryan/.ssh/authorized_keys && sudo chown ryan /home/ryan/.ssh/authorized_keys && sudo chmod 600 /home/ryan/.ssh/authorized_keys && sudo echo 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMx78nvqVe1nnln04c9KCZM0gtV5xTyxrtvFkoxL/NA9hTC9zUYNC4Tw/WDHV0JY0gmunvNvEEfjEjkRsjaL4xs= ryan@webgap.io' >> /home/ryan/.ssh/authorized_keys
    mkdir /home/jun/.ssh && sudo chown jun /home/jun/.ssh && sudo chmod 700 /home/jun/.ssh && sudo touch /home/jun/.ssh/authorized_keys && sudo chown jun /home/jun/.ssh/authorized_keys && sudo chmod 600 /home/jun/.ssh/authorized_keys && sudo echo 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOitLpmSRgHqeucnSFCJLoEnSJVZzBBAxnRJ6nXqWBouctAKNK85y2pC98zJVMUVgC292vlOSF6RBUbGkmrjaGg= jun@webgap.io' >> /home/jun/.ssh/authorized_keys

    #passwordless sudo for wheel
    sed -i '110 s/^#//' /etc/sudoers

    #ssh hardening
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

    #delete root account password
    passwd -d root

    #prohibit null password logins via pam
    sed -i 's/auth        sufficient    pam_unix.so try_first_pass nullok/auth        sufficient    pam_unix.so try_first_pass/' /etc/pam.d/system-auth
    sed -i 's/password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow/password    sufficient    pam_unix.so try_first_pass use_authtok sha512 shadow/' /etc/pam.d/system-auth
fi