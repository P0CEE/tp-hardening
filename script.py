import psutil
import pwd
import grp
import os
from datetime import datetime

class ServerHardener:
   def secure_processes(self):
       print("\n=== Top 5 processus par utilisation CPU ===")
       processes = []
       for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
           try:
               processes.append(proc.info)
           except (psutil.NoSuchProcess, psutil.AccessDenied):
               pass
       
       top_5 = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:5]
       for proc in top_5:
           print(f"PID: {proc['pid']} | Nom: {proc['name']} | CPU: {proc['cpu_percent']}% | RAM: {round(proc['memory_percent'], 1)}%")

   def secure_users(self):
       print("\n=== Utilisateurs et shells ===")
       for user in pwd.getpwall():
           if '/bin/bash' in user.pw_shell or '/bin/sh' in user.pw_shell:
               groups = [g.gr_name for g in grp.getgrall() if user.pw_name in g.gr_mem]
               print(f"Utilisateur: {user.pw_name} | Shell: {user.pw_shell} | Groupes: {', '.join(groups)}")
       
       print("\n=== Connexions actives ===")
       for user in psutil.users():
           started = datetime.fromtimestamp(user.started).strftime('%Y-%m-%d %H:%M')
           print(f"Utilisateur: {user.name} | Terminal: {user.terminal} | Démarré: {started}")

   def secure_file_permissions(self):
       print("\n=== Permissions fichiers critiques ===")
       critical_files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config"]
       for file in critical_files:
           try:
               stat = os.stat(file)
               print(f"{file}: {oct(stat.st_mode)[-3:]} | Proprio: {pwd.getpwuid(stat.st_uid).pw_name}")
           except:
               continue

   def secure_open_ports(self):
       print("\n=== Ports ouverts critiques ===")
       critical_ports = [22, 80, 443]  
       for conn in psutil.net_connections():
           if conn.status == 'LISTEN' and conn.laddr.port in critical_ports:
               try:
                   proc = psutil.Process(conn.pid)
                   print(f"Port: {conn.laddr.port} | Service: {proc.name()} | PID: {conn.pid}")
               except:
                   continue

   def secure_sudoers(self):
       print("\n=== Utilisateurs sudo ===")
       try:
           sudo_group = grp.getgrnam('sudo')
           for user in sudo_group.gr_mem:
               print(f"Utilisateur sudo: {user}")
       except:
           print("Groupe sudo non trouvé")

   def secure_ssh(self):
       print("\n=== Configuration SSH ===")
       ssh_config = "/etc/ssh/sshd_config"
       critical_settings = ["PermitRootLogin", "PasswordAuthentication", "Port", "X11Forwarding"]
       
       try:
           with open(ssh_config, 'r') as f:
               content = f.readlines()
               
           for line in content:
               for setting in critical_settings:
                   if line.strip().startswith(setting):
                       print(f"{line.strip()}")
       except:
           print("Impossible d'accéder à la configuration SSH")

   def generate_html_report(self):
       html = f"""
       <html>
       <head>
           <title>Rapport de Sécurité</title>
           <style>
               body {{ font-family: Arial; margin: 40px; }}
               h1 {{ color: #2c3e50; text-align: center; }}
               h2 {{ color: #34495e; margin-top: 30px; }}
               table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
               th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
               th {{ background-color: #f5f5f5; }}
               tr:nth-child(even) {{ background-color: #f9f9f9; }}
           </style>
       </head>
       <body>
           <h1>Rapport de Sécurité - {datetime.now().strftime("%Y-%m-%d %H:%M")}</h1>
           
           <h2>Processus Critiques</h2>
           <table>
               <tr><th>PID</th><th>Nom</th><th>CPU %</th><th>RAM %</th></tr>
       """

       processes = []
       for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
           try:
               processes.append(proc.info)
           except:
               continue
       
       top_5 = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:5]
       for proc in top_5:
           html += f"<tr><td>{proc['pid']}</td><td>{proc['name']}</td><td>{proc['cpu_percent']}%</td><td>{round(proc['memory_percent'], 1)}%</td></tr>"

       html += """
           </table>
           <h2>Utilisateurs et Shells</h2>
           <table>
               <tr><th>Utilisateur</th><th>Shell</th><th>Groupes</th></tr>
       """
       
       for user in pwd.getpwall():
           if '/bin/bash' in user.pw_shell or '/bin/sh' in user.pw_shell:
               groups = [g.gr_name for g in grp.getgrall() if user.pw_name in g.gr_mem]
               html += f"<tr><td>{user.pw_name}</td><td>{user.pw_shell}</td><td>{', '.join(groups)}</td></tr>"

       html += """
           </table>
           <h2>Fichiers Critiques</h2>
           <table>
               <tr><th>Fichier</th><th>Permissions</th><th>Propriétaire</th></tr>
       """
       
       critical_files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config"]
       for file in critical_files:
           try:
               stat = os.stat(file)
               html += f"<tr><td>{file}</td><td>{oct(stat.st_mode)[-3:]}</td><td>{pwd.getpwuid(stat.st_uid).pw_name}</td></tr>"
           except:
               continue

       html += """
           </table>
           <h2>Ports Ouverts</h2>
           <table>
               <tr><th>Port</th><th>Service</th><th>PID</th></tr>
       """
       
       critical_ports = [22, 80, 443]
       for conn in psutil.net_connections():
           if conn.status == 'LISTEN' and conn.laddr.port in critical_ports:
               try:
                   proc = psutil.Process(conn.pid)
                   html += f"<tr><td>{conn.laddr.port}</td><td>{proc.name()}</td><td>{conn.pid}</td></tr>"
               except:
                   continue

       html += """
           </table>
           <h2>Configuration SSH</h2>
           <table>
               <tr><th>Paramètre</th><th>Valeur</th></tr>
       """

       ssh_config = "/etc/ssh/sshd_config"
       critical_settings = ["PermitRootLogin", "PasswordAuthentication", "Port", "X11Forwarding"]
       try:
           with open(ssh_config, 'r') as f:
               content = f.readlines()
           for line in content:
               for setting in critical_settings:
                   if line.strip().startswith(setting):
                       param, value = line.strip().split(None, 1)
                       html += f"<tr><td>{param}</td><td>{value}</td></tr>"
       except:
           html += "<tr><td colspan='2'>Impossible d'accéder à la configuration SSH</td></tr>"

       html += """
           </table>
       </body>
       </html>
       """

       with open('rapport_securite.html', 'w') as f:
           f.write(html)
           print("\nRapport HTML généré dans 'rapport_securite.html'")

   def run_hardening(self):
       print(f"=== Audit sécurité - {datetime.now()} ===")
       self.secure_processes()
       self.secure_users()
       self.secure_file_permissions()
       self.secure_open_ports()
       self.secure_sudoers()
       self.secure_ssh()
       self.generate_html_report()

if __name__ == "__main__":
   hardener = ServerHardener()
   hardener.run_hardening()