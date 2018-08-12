sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo /sbin/iptables-save
