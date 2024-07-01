# SpoofTarea<br>
Alumno: Daniel Cabrera García<br>
Grupo: 6CV2<br>
+ Primero se tiene que hacer ping en ambas computadoras, por ejemplo ping de kali a ubuntu y viceversa<br>
+ Como siguiente paso es correr en la máquina atacada el script de contraspoof.py; sin embargo para esto hay que crear un ambiente virtual de python en el cual se tiene que instalar la librería de scapy con pip install, despues habrá que dirigirse a la ubicación donde se descargó el archivo para finalmente ejecutar el archivo con el comando python3 contraspoof.py. Como paréntesis en mi caso para correrlo tuve que poner la ruta hacia la librería python3: sudo /home/danielc/Desktop/myenv/bin/python3 contraspoof.py. Y finalmente aparecerá si la computadora ha sido vulnerada para asi restaurar la tabla ARP de la IP afectada a su estado original.<br>
+ Después se corre el programa de spoof en la máquina atacante dirigiéndose a la locación del archivo desde la terminal y ejecutando el comando python3 spoof.py después se tendra que escribir manualmente la dirección del router asi como la dirección de la máquina a atacar para poder ejecutar los comandos de arp automáticamente. Ya solo restará ejecutar el comando arp -n en la máquina atacada para poder visualizar el ataque, en el cual aparecera la dirección mac modificada.<br>
+ 
