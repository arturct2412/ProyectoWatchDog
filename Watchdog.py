import threading
import time
import psutil
import GPUtil
import tkinter as tk
from PIL import Image, ImageDraw, ImageFont, ImageTk
import subprocess
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import wmi
import winreg as reg
from tkinter import messagebox
import socket
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt


def create_circle_image(size, width, progress, text):
    # Crear una nueva imagen
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Calcular el ángulo de la barra de progreso
    start_angle = 90  # Empieza desde la posición de las 12 en punto
    end_angle = start_angle + (progress * 3.6)  # 3.6 grados por cada 1% de progreso

    # Dibujar el arco de la barra de progreso
    draw.arc([(width, width), (size - width, size - width)], start_angle, end_angle, fill=(0, 128, 0), width=width)

    # Establecer la fuente y el tamaño del texto
    font = ImageFont.truetype("mandalore.ttf", 24)

    # Obtener las dimensiones del texto
    text_width, text_height = draw.textsize(text, font=font)

    # Calcular la posición del texto centrado dentro del círculo
    text_x = (size - text_width) // 2
    text_y = (size - text_height) // 2

    # Escribir el porcentaje dentro del círculo
    draw.text((text_x, text_y), text, font=font, fill=(255, 255, 255))

    return image

def identify_open_ports():
    # Obtener la dirección IP del host
    target_ip = socket.gethostbyname(socket.gethostname())

    result = subprocess.run(["nmap", "-p", "1-65535", "-T4", "-Pn", target_ip], capture_output=True, text=True)
    open_ports = []
    for line in result.stdout.splitlines():
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0]
            open_ports.append(port)
    open_ports_str = ', '.join(open_ports)
    tk.messagebox.showinfo("Puertos abiertos", f"Los puertos abiertos son: {open_ports_str}")

def services_on_ports():
    # Obtener la dirección IP del host
    target_ip = socket.gethostbyname(socket.gethostname())

    result = subprocess.run(["nmap", "-p", "1-65535", "-T4", "-Pn", "--open", target_ip], capture_output=True, text=True)
    services = []
    for line in result.stdout.splitlines():
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0]
            service = line.split("open")[1].strip()
            services.append(f"Servicio en puerto {port}: {service}")
    services_str = '\n'.join(services)
    tk.messagebox.showinfo("Servicios en puertos abiertos", f"Los servicios en puertos abiertos son:\n\n{services_str}")

def scan_vulnerabilities():
    # Obtener la dirección IP del host
    target_ip = socket.gethostbyname(socket.gethostname())
    print(f"Escaneando vulnerabilidades en la dirección IP: {target_ip}")

    # Ejecutar el escaneo de vulnerabilidades con Nmap
    result = subprocess.run(['nmap', '-p', '1-1000', '-sV', '-oX', 'scan.xml', target_ip], capture_output=True)

    if result.returncode == 0:
        print("Escaneo con éxito")
        show_vulnerabilities_window()
    else:
        print("Ocurrió un error")

def show_vulnerabilities_window():
    vulnerabilities_window = tk.Toplevel()
    vulnerabilities_window.title("Vulnerabilidades")
    vulnerabilities_window.geometry("600x400")
    vulnerabilities_window.configure(bg="#333333")

    scrollbar = tk.Scrollbar(vulnerabilities_window)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_area = tk.Text(vulnerabilities_window, yscrollcommand=scrollbar.set, bg="#FFFFFF", fg="#000000")
    text_area.pack(expand=True, fill=tk.BOTH)

    scrollbar.config(command=text_area.yview)

    try:
        with open("scan.xml", "r") as xml_file:
            xml_content = xml_file.read()
            # Parsear el contenido XML
            xml_dom = minidom.parseString(xml_content)
            # Obtener el contenido formateado con indentación y espacios en blanco
            formatted_xml = xml_dom.toprettyxml()
            # Mostrar el contenido en el área de texto
            text_area.insert(tk.END, formatted_xml)
    except FileNotFoundError:
        text_area.insert(tk.END, "Archivo scan.xml no encontrado.")

def check_usb_devices():
    c = wmi.WMI()
    usb_devices = c.Win32_USBHub()
    usb_info = []

    for device in usb_devices:
        # Obtener el estado del puerto USB (ocupado o libre)
        if device.Status == "OK":
            status = "Libre"
        else:
            status = "Ocupado"

        # Agregar la información del puerto USB a la lista
        usb_info.append(f"Puerto: {device.DeviceID}\nEstado: {status}\n")

    return usb_info


def show_usb_devices():
    usb_info = check_usb_devices()

    if usb_info:
        usb_text = "\n".join(usb_info)
    else:
        usb_text = "No se encontraron dispositivos USB conectados."

    usb_window = tk.Toplevel()
    usb_window.title("Puertos USB")
    usb_window.geometry("400x300")

    usb_label = tk.Label(usb_window, text=usb_text)
    usb_label.pack()

def disable_usb_ports():
    try:
        # Abrir la clave de registro para los controladores USB
        reg_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, reg.KEY_SET_VALUE)

        # Modificar el valor Start para deshabilitar los controladores USB
        reg.SetValueEx(reg_key, "Start", 0, reg.REG_DWORD, 4)

        reg_key.Close()

        print("Los puertos USB han sido deshabilitados correctamente.")
    except Exception as e:
        print(f"Error al deshabilitar los puertos USB: {str(e)}")


def enable_usb_ports():
    try:
        # Abrir la clave de registro para los controladores USB
        reg_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, reg.KEY_SET_VALUE)

        # Modificar el valor Start para habilitar los controladores USB
        reg.SetValueEx(reg_key, "Start", 0, reg.REG_DWORD, 3)

        reg_key.Close()

        print("Los puertos USB han sido habilitados correctamente.")
    except Exception as e:
        print(f"Error al habilitar los puertos USB: {str(e)}")

def show_confirmation_window(device_name):
    result = messagebox.askyesno("Confirmación", f"¿Desea permitir la conexión del dispositivo USB '{device_name}'?")

    if result:
        messagebox.showinfo("Conexión permitida", f"Se ha permitido la conexión del dispositivo USB '{device_name}'.")
    else:
        messagebox.showwarning("Conexión denegada", f"Se ha denegado la conexión del dispositivo USB '{device_name}'.")


def watch_usb_devices():
    usb_devices_before = check_usb_devices()

    while True:
        usb_devices_after = check_usb_devices()

        if len(usb_devices_after) > len(usb_devices_before):
            new_device = list(set(usb_devices_after) - set(usb_devices_before))
            device_name = new_device[0].split("\n")[0].split(": ")[1]
            threading.Thread(target=show_confirmation_window, args=(device_name,)).start()

        usb_devices_before = usb_devices_after

def generate_memory_chart():
    memory_percent = psutil.virtual_memory().percent

    fig, ax = plt.subplots()
    ax.bar(["Memoria"], [memory_percent], color="#303F9F")

    ax.text(0, memory_percent, str(memory_percent) + "%", ha='center', va='bottom')

    ax.set_ylim(0, 100)
    ax.set_ylabel('Porcentaje de uso')
    ax.set_title('Uso de memoria')
    ax.spines['bottom'].set_color('#616161')
    ax.spines['left'].set_color('#616161')

    fig.patch.set_facecolor('#424242')
    ax.set_facecolor('#424242')
    ax.tick_params(colors='#FFFFFF')
    ax.yaxis.label.set_color('#FFFFFF')
    ax.xaxis.label.set_color('#FFFFFF')
    ax.title.set_color('#FFFFFF')

    canvas = FigureCanvasTkAgg(fig, master=ventana)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=10)

def get_gpu_info():
    gpus = GPUtil.getGPUs()
    gpu_info = []
    for gpu in gpus:
        gpu_info.append(f"GPU: {gpu.name}")
        gpu_info.append(f"Memoria utilizada: {gpu.memoryUsed} MB")
        gpu_info.append(f"Memoria total: {gpu.memoryTotal} MB")
        gpu_info.append(f"Porcentaje de uso: {gpu.load*100}%")
        gpu_info.append(f"Temperatura: {gpu.temperature} °C")
        gpu_info.append("")
    gpu_info_str = '\n'.join(gpu_info)
    tk.messagebox.showinfo("Información de la GPU", gpu_info_str)

def get_cpu_info():
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_info = []
    cpu_info.append("Uso de CPU: " + str(cpu_percent) + "%")
    for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        cpu_info.append("Uso de CPU por núcleo " + str(i) + ": " + str(percentage) + "%")
    cpu_info_str = '\n'.join(cpu_info)
    tk.messagebox.showinfo("Información de la CPU", cpu_info_str)

def get_memory_info():
    memory = psutil.virtual_memory()
    memory_info = []
    memory_info.append("Memoria total: " + str(memory.total >> 20) + " MB")
    memory_info.append("Memoria disponible: " + str(memory.available >> 20) + " MB")
    memory_info.append("Porcentaje de uso: " + str(memory.percent) + "%")
    memory_info.append("Memoria usada: " + str(memory.used >> 20) + " MB")
    memory_info_str = '\n'.join(memory_info)
    tk.messagebox.showinfo("Información de la memoria", memory_info_str)

def get_disk_info():
    disk_info = []
    for partition in psutil.disk_partitions():
        partition_info = psutil.disk_usage(partition.mountpoint)
        disk_info.append("Disco: " + partition.device)
        disk_info.append("Punto de montaje: " + partition.mountpoint)
        disk_info.append("Sistema de archivos: " + partition.fstype)
        disk_info.append("Espacio total: " + str(partition_info.total >> 30) + " GB")
        disk_info.append("Espacio utilizado: " + str(partition_info.used >> 30) + " GB")
        disk_info.append("Espacio disponible: " + str(partition_info.free >> 30) + " GB")
        disk_info.append("Porcentaje de uso: " + str(partition_info.percent) + "%")
        disk_info.append("")
    disk_info_str = '\n'.join(disk_info)
    tk.messagebox.showinfo("Información del disco", disk_info_str)

def watchdog():

    while True:
        # Actualizar los indicadores visuales
        cpu_percent = psutil.cpu_percent()
        gpu_percent = GPUtil.getGPUs()[0].load * 100  # Porcentaje de uso de la primera GPU
        image_cpu = create_circle_image(200, 20, cpu_percent, f"CPU\n{int(cpu_percent)}%")
        photo_cpu = ImageTk.PhotoImage(image_cpu)
        barra_progreso_cpu.config(image=photo_cpu)
        barra_progreso_cpu.image = photo_cpu  # Actualizar referencia a la imagen para evitar el recolector de basura
        image_gpu = create_circle_image(200, 20, gpu_percent, f"GPU\n{int(gpu_percent)}%")
        photo_gpu = ImageTk.PhotoImage(image_gpu)
        barra_progreso_gpu.config(image=photo_gpu)
        barra_progreso_gpu.image = photo_gpu  # Actualizar referencia a la imagen para evitar el recolector de basura

        time.sleep(2)

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("WatchDog ARTHZET")
ventana.geometry("1000x900")
ventana.configure(bg="#333333")

button_frame = tk.Frame(ventana, bg='#424242')
button_frame.pack(pady=10)

# Botón para iniciar el escaneo de vulnerabilidades
button_scan = tk.Button(ventana, text="Escanear vulnerabilidades", command=scan_vulnerabilities, bg='#212121', fg='#FFFFFF')
button_scan.pack(pady=10)

button_ports = tk.Button(ventana, text="Identificar Puertos Abiertos", command=identify_open_ports, bg='#212121', fg='#FFFFFF')
button_ports.pack(pady=10)

button_services = tk.Button(ventana, text="Identificar Servicios en Puertos Abiertos", command=services_on_ports, bg='#212121', fg='#FFFFFF')
button_services.pack(pady=10)

# Botón para mostrar los dispositivos USB
btn_usb = tk.Button(ventana, text="Puertos USB", command=show_usb_devices, bg='#212121', fg='#FFFFFF')
btn_usb.pack(pady=10)

disk_button = tk.Button(ventana, text="Discos", command=get_disk_info, bg='#212121', fg='#FFFFFF')
disk_button.pack(pady=10)

# Frame para mostrar los indicadores de CPU y GPU
frame_indicadores = tk.Frame(ventana, bg="#333333")
frame_indicadores.pack(pady=10)

# Indicador de CPU
barra_progreso_cpu = tk.Label(frame_indicadores, bg="#333333")
barra_progreso_cpu.pack(side=tk.LEFT, padx=10)
cpu_button = tk.Button(ventana, text="CPU", command=get_cpu_info, bg='#212121', fg='#FFFFFF')
cpu_button.pack(padx=10)

# Indicador de GPU
barra_progreso_gpu = tk.Label(frame_indicadores, bg="#333333")
barra_progreso_gpu.pack(side=tk.LEFT, padx=10)
gpu_button = tk.Button(ventana, text="GPU", command=get_gpu_info, bg='#212121', fg='#FFFFFF')
gpu_button.pack(padx=10)

# Hilo para actualizar los indicadores
watchdog_thread = threading.Thread(target=watchdog)
watchdog_thread.daemon = True
watchdog_thread.start()

generate_memory_chart()

# Bloquear los puertos USB al iniciar el programa
disable_usb_ports()

# Iniciar el hilo de monitoreo de dispositivos USB
threading.Thread(target=watch_usb_devices).start()

# Iniciar el bucle principal de la ventana
ventana.mainloop()

# Habilitar los puertos USB al cerrar el programa
enable_usb_ports()


