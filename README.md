# TP HARDENING

# Documentation Technique - Audit de Sécurité Linux

## Documentation Technique

### Structure du Code

- **ServerHardener** : Classe principale gérant l'audit
- **Méthodes principales** :
    - `secure_processes()` : Surveillance processus (psutil)
    - `secure_users()` : Analyse utilisateurs (pwd, grp)
    - `secure_file_permissions()` : Vérification permissions
    - `secure_open_ports()` : Scan ports (psutil.net_connections)
    - `secure_ssh()` : Audit SSH
    - `generate_html_report()` : Génération rapport HTML

### Dépendances

```python
import psutil# Surveillance système
import pwd# Infos utilisateurs
import grp# Infos groupes
import os# Opérations fichiers
from datetime import datetime
```

## Documentation Fonctionnelle

### Fonctionnalités Détaillées

1. **Monitoring Processus**
    - Top 5 processus par CPU/RAM
    - Infos : PID, nom, %CPU, %RAM
2. **Gestion Utilisateurs**
    - Liste utilisateurs avec shell
    - Groupes associés
    - Sessions actives et durée
3. **Sécurité Fichiers**
    - Vérification fichiers critiques:
        - /etc/shadow
        - /etc/passwd
        - /etc/sudoers
        - /etc/ssh/sshd_config
    - Analyse permissions et propriétaires
4. **Réseau**
    - Scan ports critiques (22, 80, 443)
    - Détails services associés
5. **Configuration SSH**
    - Paramètres critiques:
        - PermitRootLogin
        - PasswordAuthentication
        - Port
        - X11Forwarding

### Sortie

- Console : Affichage en temps réel
- HTML : Rapport formaté avec tables et styles CSS

### Utilisation

```bash
pip3 install psutil
python3 script.py
```