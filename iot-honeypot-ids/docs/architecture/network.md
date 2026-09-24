# Network topology

## Physical layout

```
                 ROUTER (ordinary LAN, no VLANs required)
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
       Pi 4        PC1         PC2
   192.168.1.50  192.168.1.10  192.168.1.20
   Honeypot fleet ELK + ML    Attacker
```

All three machines are on the same subnet. No special router features
required. If the router supports VLANs / firewall APIs / port mirroring /
OpenWrt, the system can use them optionally — see
[`optional-router-features.md`](optional-router-features.md).

## Required ports

### Pi 4 (192.168.1.50)

| Port  | Protocol | Direction        | Purpose                              |
|-------|----------|------------------|--------------------------------------|
| 2222  | TCP      | inbound (from PC2) | Cowrie SSH honeypot               |
| 2223  | TCP      | inbound (from PC2) | Cowrie Telnet honeypot            |
| 8080  | TCP      | inbound (from PC2) | Camera HTTP honeypot              |
| 9000  | TCP      | inbound (from PC2) | IoT service honeypot              |
| 22    | TCP      | inbound (from PC1) | SSH administration (host, NOT honeypot) |
| 5044  | TCP      | outbound (to PC1)  | Filebeat → Logstash              |

### Computer 1 (192.168.1.10)

| Port  | Protocol | Direction        | Purpose                              |
|-------|----------|------------------|--------------------------------------|
| 5044  | TCP      | inbound (from Pi)| Logstash Beats input                 |
| 9200  | TCP      | inbound (lab only)| Elasticsearch HTTP API             |
| 5601  | TCP      | inbound (lab only)| Kibana                              |
| 8000  | TCP      | inbound (lab only)| FastAPI dashboard API              |
| 3000  | TCP      | inbound (lab only)| React dev server (optional)        |

### Computer 2 (192.168.1.20)

| Port  | Protocol | Direction        | Purpose                              |
|-------|----------|------------------|--------------------------------------|
| —     | outbound | to Pi only       | Attack traffic to honeypot ports     |

PC2 only initiates outbound connections to the Pi's honeypot ports.
It does not need any inbound ports.

## Firewall hints (optional)

If you want a host firewall on the Pi (recommended):

```bash
# Allow SSH admin from anywhere in the lab
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp

# Allow honeypot ports from the lab (PC2 will be the only one using these)
sudo ufw allow from 192.168.1.0/24 to any port 2222 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 2223 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 9000 proto tcp

# Allow outbound Beats to PC1
sudo ufw allow out to 192.168.1.10 port 5044 proto tcp

# Enable
sudo ufw enable
```

On PC1 (Fedora):

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.50/32 port port=5044 protocol=tcp accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=5601 protocol=tcp accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=8000 protocol=tcp accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=9200 protocol=tcp accept'
sudo firewall-cmd --reload
```

On Windows: use Windows Defender Firewall with the equivalent inbound rules.
