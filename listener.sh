#!/bin/bash
echo "This program will start a listener for a reverse ssh..."

# Make sure OpenSSH is installed and running
sudo pacman -S --noconfirm openssh
sudo systemctl enable sshd
sudo systemctl start sshd

# Allow SSH through firewall
sudo ufw allow 22/tcp

while true; do
  echo -n "Input target username (Windows user): "
  read targetusername
  clear
  echo "You entered $targetusername , correct? y/n :"
  read correction
  if [ "$correction" = "y" ]; then
    # Connect to the Windows host on port 9000
    ssh -p 9000 "$targetusername@localhost"
    break
  elif [ "$correction" = "n" ]; then
    echo "Let's try again..."
  else
    echo "Invalid input..."
  fi
done
