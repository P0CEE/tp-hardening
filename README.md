# TP HARDENING - Documentation Technique et Fonctionnelle

## 1. Documentation Technique

### Architecture

### Classe ServerHardener

- **Initialisation**
    
    ```python
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader('.'))
        self.template = self.env.get_template('report_template.html')
        os.makedirs('output', exist_ok=True)
    
    ```
    
    - Configuration Jinja2 environnement
    - Chargement template depuis dossier courant
    - Création dossier output

### Méthodes Détaillées

### collect_process_data()

```python
def collect_process_data(self):
    processes = []
    return {
        'cpu': cpu_processes,# Top 5 CPU
        'ram': ram_processes# Top 5 RAM
    }

```

- Utilise `psutil.process_iter()`
- Capture: PID, nom, CPU%, RAM%, temps démarrage
- Trie processus par CPU/RAM
- Gestion exceptions: NoSuchProcess, AccessDenied

### collect_user_data()

```python
def collect_user_data(self):
    users = []
    return users
```

- Utilise `pwd.getpwall()`
- Filtre shells: /bin/bash, /bin/sh
- Mappe utilisateurs-groupes via grp

### collect_file_data()

```python
def collect_file_data(self):
    files = []
    critical_files = ["/etc/shadow", ...]
    return files
```

- Scan fichiers critiques
- Utilise `os.stat()` pour permissions
- Format octal pour permissions
- Résolution propriétaires via pwd

### collect_port_data()

```python
def collect_port_data(self):
    ports = []
    critical_ports = [22, 80, 443]
    return ports
```

- Utilise `psutil.net_connections()`
- Filtre état LISTEN
- Résolution processus associés

### collect_sudoers_data()

```python
def collect_sudoers_data(self):
    sudoers = []
    return sudoers
```

- Double vérification:
    1. Groupe sudo
    2. Fichier /etc/sudoers
- Détection pattern ALL=(ALL:ALL) ALL

### collect_ssh_data()

```python
def collect_ssh_data(self):
    settings = []
    critical_settings = ["PermitRootLogin", ...]
    return settings

```

- Parse /etc/ssh/sshd_config
- Focus paramètres sécurité critiques
- Extraction valeurs configuration

### Génération Rapport

```python
def generate_report(self):
    data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
```

- Centralisation données collectées
- Rendu template Jinja2
- Sortie fichier HTML

## 2. Documentation Fonctionnelle

### Fonctionnalités

1. **Monitoring Processus**
    - Top 5 CPU et RAM
    - Données: PID, nom, utilisation, temps démarrage
    - Commande associée
2. **Audit Utilisateurs**
    - Liste utilisateurs avec shell
    - Groupes associés
    - Droits sudo et origine
3. **Sécurité Système**
    - Fichiers critiques (/etc/shadow, /etc/passwd...)
    - Ports sensibles (22, 80, 443)
    - Configuration SSH
4. **Rapport HTML**
    - Tables formatées
    - Styles CSS intégrés
    - Stockage dans `output/`

### Prérequis et Installation

```bash
python3 
pip install -r requirements.txt
```

### Utilisation

```bash
python3 hardening.py
# Rapport généré dans: output/rapport_securite.html
```

### Droits Requis

- Root/sudo pour:
    - Accès fichiers système
    - Scan processus
    - Analyse ports

## 4. Structure du Code

```
hardening/
├── hardening.py
├── report_template.html
├── requirements.txt
└── output/
```