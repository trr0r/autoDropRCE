# Backdrop CMS 1.27.1 - Automated Authenticated RCE

Este [script](<autoDropRCE.py>) permite obtener acceso de forma automatizada a la máquina víctima sobre una instalación vulnerable de **Backdrop CMS 1.27.1**. La vulnerabilidad explotada radica en la gestión de módulos, donde el atacante puede subir e instalar un módulo malicioso en el sistema.

Las opciones disponibles son las siguientes:

```ps
usage: autoDropRCE.py [-h] -t TARGET_URL -h-ip HOST_IP -u USERNAME -p PASSWORD [-l PORT]

🪂 Backdrop CMS 1.27.1 - Automated Authenticated RCE 🪂

   ej: python3 autoDropRCE.py -t http://backdrop-example.com -h-ip 172.17.0.1 -u trr0r -p trr0r

options:
  -h, --help                   show this help message and exit
  -t, --target-url TARGET_URL  Target url Backdrop web - ej: http://backdrop-example.com
  -h-ip, --host-ip HOST_IP     Host IP - ej: 172.17.0.1
  -u, --username   USERNAME    Valid Backdrop username - ej: trr0r
  -p, --password   PASSWORD    Valid Backdrop password - ej: trr0r
   
  -l, --listen-port PORT       Listen port                                         (default = 4444)
```

___
## Descripción de la Vulnerabilidad 📜

En el gestor de contenidos **Backdrop** (**1.27.1**) un atacante puede subir módulos maliciosos al sistema. Esto se debe a una debilidad en la forma en que **Backdrop** maneja la carga de módulos a través del **instalador manual de módulos**, lo que facilita la ejecución remota de comandos (**RCE**).
### 1. Módulo Malicioso:

El atacante debe de crear un módulo `.tar` que contenga:
- Un archivo `.php` con código malicioso, como una **web shell**, que permita ejecutar comandos de manera remota (**RCE**).
- Un archivo `.info` que describa el módulo para que así sea registrado como un módulo válido para el sistema **Backdrop CMS**.
### 2. Subida del Módulo:

Para aprovechar esta vulnerabilidad, el atacante necesita autenticarse en **Backdrop CMS**. Una vez autenticado, y si tiene los permisos adecuados, podrá cargar e instalar un módulo malicioso. Este módulo, al ser instalado en el sistema, permitirá al atacante ejecutar comandos de manera remota en el servidor (RCE).

___
## Descarga 📥

Nos clonamos el repositorio de la siguiente forma:

```bash
git clone https://github.com/trr0r/autoDropRCE
cd autoDropRCE
```

Instalamos las librerías necesarias gracias a `pip3`:

```bash
pip3 install -r requirements.txt
```

___
## Uso ⚙️

Una vez que tengas los datos listos, puedes ejecutar el script con el siguiente comando:

```bash
python3 autoDropRCE.py -t http://backdrop-example.com -h-ip 172.17.0.1 -u trr0r -p trr0r
```

![Image](https://github.com/user-attachments/assets/d654ae24-a00d-46d6-9127-facdb019c326)

---
### Advertencia legal ⚠️

> [!WARNING]
Este software está destinado solo para uso personal y debe utilizarse únicamente en entornos controlados y con autorización previa. El empleo de esta herramienta en sistemas o redes sin la debida autorización puede ser ilegal y contravenir políticas de seguridad. El desarrollador no se hace responsable de daños, pérdidas o consecuencias resultantes de su uso inapropiado o no autorizado. Antes de utilizar esta herramienta, asegúrate de cumplir con todas las leyes y regulaciones locales pertinentes.