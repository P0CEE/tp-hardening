import psutil
import pwd
import grp
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class ServerHardener:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader('.'))
        self.template = self.env.get_template('report_template.html')
        os.makedirs('output', exist_ok=True)
        
    def collect_process_data(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                process = proc.info
                process['memory_percent'] = round(process['memory_percent'], 1)
                p = psutil.Process(process['pid'])
                process['create_time'] = datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M')
                process['command'] = ' '.join(p.cmdline())[:100] if p.cmdline() else 'N/A'
                processes.append(process)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        cpu_processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:5]
        ram_processes = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:5]

        return {
            'cpu': cpu_processes,
            'ram': ram_processes
        }

    def collect_user_data(self):
        users = []
        for user in pwd.getpwall():
            if '/bin/bash' in user.pw_shell or '/bin/sh' in user.pw_shell:
                groups = [g.gr_name for g in grp.getgrall() if user.pw_name in g.gr_mem]
                users.append({
                    'name': user.pw_name,
                    'shell': user.pw_shell,
                    'groups': ', '.join(groups)
                })
        return users

    def collect_file_data(self):
        files = []
        critical_files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config"]
        for file in critical_files:
            try:
                stat = os.stat(file)
                files.append({
                    'path': file,
                    'permissions': oct(stat.st_mode)[-3:],
                    'owner': pwd.getpwuid(stat.st_uid).pw_name
                })
            except:
                continue
        return files

    def collect_port_data(self):
        ports = []
        critical_ports = [22, 80, 443]
        for conn in psutil.net_connections():
            if conn.status == 'LISTEN' and conn.laddr.port in critical_ports:
                try:
                    proc = psutil.Process(conn.pid)
                    ports.append({
                        'number': conn.laddr.port,
                        'service': proc.name(),
                        'pid': conn.pid
                    })
                except:
                    continue
        return ports
    
    def collect_sudoers_data(self):
        sudoers = []
        try:
            sudo_group = grp.getgrnam('sudo')
            for user in sudo_group.gr_mem:
                sudoers.append({'name': user, 'type': 'group_sudo'})
            
            with open('/etc/sudoers', 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        if 'ALL=(ALL:ALL) ALL' in line:
                            user = line.split()[0]
                            if user not in [s['name'] for s in sudoers]:
                                sudoers.append({'name': user, 'type': 'sudoers_file'})
        except:
            pass
        return sudoers

    def collect_ssh_data(self):
        settings = []
        critical_settings = ["PermitRootLogin", "PasswordAuthentication", "Port", "X11Forwarding"]
        try:
            with open("/etc/ssh/sshd_config", 'r') as f:
                for line in f:
                    for setting in critical_settings:
                        if line.strip().startswith(setting):
                            param, value = line.strip().split(None, 1)
                            settings.append({'param': param, 'value': value})
        except:
            pass
        return settings

    def generate_report(self):
        data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M"),
            'processes': self.collect_process_data(),
            'users': self.collect_user_data(),
            'critical_files': self.collect_file_data(),
            'open_ports': self.collect_port_data(),
            'sudoers': self.collect_sudoers_data(),
            'ssh_config': self.collect_ssh_data(),
        }
        
        html_content = self.template.render(**data)
        output_path = os.path.join('output', 'rapport_securite.html')
        with open(output_path, 'w') as f:
            f.write(html_content)
        print(f"Rapport HTML généré dans {output_path}")

    def run_hardening(self):
        print(f"=== Audit sécurité - {datetime.now()} ===")
        self.generate_report()

if __name__ == "__main__":
    hardener = ServerHardener()
    hardener.run_hardening()