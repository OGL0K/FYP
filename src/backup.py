import os
import io
import segno
import sys
import json
import shutil
import base64
import shamirs
import subprocess
import customtkinter
import tkinter as tk

from natsort import natsorted
from tkinter import messagebox
from PIL import Image, ImageFont, ImageDraw
import main_window

customtkinter.set_appearance_mode("System")

#Paths
pwd = os.path.expanduser('~')
qr_path = f"{pwd}/Documents/.QR-Code"
final_qr_path = f'{pwd}/Documents/PassQR'

#Global Variables
decrypted_data = []
sym_passp = ""
replay = 0
error_count = 3
re_passp_error_count = 3
prime = 885911280445661314349040360393507317170478541097150373342910055055679257

def disable_close():
    pass

def cancel_convert(self, window):
    if messagebox.askyesno('Cancel Backup', 'Are you sure to cancel your backup process?', parent=window):
        global error_count
        global re_passp_error_count
        global decrypted_data
        global sym_passp

        sym_passp = ""
        decrypted_data = []
        error_count = 3
        re_passp_error_count = 3
        window.destroy()
        main_window.App.enable_button(self)

#Setting Grid of the Image File
def set_grid(image_list, rows, collumns):
    len(image_list) == rows*collumns
    image_width, image_height = image_list[0].size
    image_grid = Image.new('RGB', (collumns*image_width, rows*image_height), (255,255,255))

    for i, image in enumerate(image_list):
        image_grid.paste(image, box=(i%collumns*image_width, i//collumns*image_height))
    return image_grid

#Combining Images
def combine_img(copy):
    global replay
    qr_file_count = 0

    if os.path.exists(final_qr_path):
        pass
    else:
        os.mkdir(final_qr_path)

    if int(copy) == 1:
        pass
    
    else:

        if replay == 0:
            original_dir = f"{final_qr_path}/Original"

            if os.path.exists(original_dir):
                shutil.rmtree(original_dir)
                os.mkdir(original_dir)
            else:
                os.mkdir(original_dir)

        else: 
            copy_dir = f"{final_qr_path}/Copy-{replay + 1}"

            if os.path.exists(copy_dir):
                shutil.rmtree(copy_dir)
                os.mkdir(copy_dir)
            else:
                os.mkdir(copy_dir)

    while True:
        qr_list = []
        qr_list2 = []
        qr_image_list = []
        qr_image_list2 = []
        
        for main_path, sub_directories, files in os.walk(qr_path):
            for name in files:
                if name.endswith('.png'):
                    joined = os.path.join(main_path, name)
                    qr_list.append(joined)

        for x in natsorted(qr_list):
            qr_image_list.append(Image.open(x))

        if len(qr_image_list) == 1:
            qr_file_count += 1
            image_file = set_grid(qr_image_list, 1, 1)
            
            if int(copy) == 1:
                image_file.save(f'{final_qr_path}/QR-File{qr_file_count}.png')
            else:
                if replay == 0:
                    image_file.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
                elif replay > 0:
                    image_file.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay + 1}.png')
            return False

        elif len(qr_image_list) == 2:
            qr_file_count += 1
            image_file = set_grid(qr_image_list, 1, 2)

            if int(copy) == 1:
                image_file.save(f'{final_qr_path}/QR-File{qr_file_count}.png')
            else:
                if replay == 0:
                    image_file.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
                elif replay > 0:
                    image_file.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay + 1}.png')
            return False

        elif len(qr_image_list) == 3 or len(qr_image_list) == 4:
            qr_file_count += 1
            image_file = set_grid(qr_image_list, 2, 2)

            if int(copy) == 1:
                image_file.save(f'{final_qr_path}/QR-File{qr_file_count}.png')
            else:
                if replay == 0:
                    image_file.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
                elif replay > 0:
                    image_file.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay + 1}.png')
            return False

        elif len(qr_image_list) == 5 or len(qr_image_list) == 6:
            qr_file_count += 1
            image_file = set_grid(qr_image_list, 2, 3)

            if int(copy) == 1:
                image_file.save(f'{final_qr_path}/QR-File{qr_file_count}.png')
            else:
                if replay == 0:
                    image_file.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
                elif replay > 0:
                    image_file.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay + 1}.png')
            return False

        elif len(qr_image_list) == 7 or len(qr_image_list) == 8 or len(qr_image_list) == 9:
            qr_file_count += 1
            image_file = set_grid(qr_image_list, 3, 3)

            if int(copy) == 1:
                image_file.save(f'{final_qr_path}/QR-File{qr_file_count}.png')
            else:
                if replay == 0:
                    image_file.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
                elif replay > 0:
                    image_file.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay + 1}.png')
            return False

        elif len(qr_image_list) >= 9:
            
            for y in range(0,9):
                qr_list2.append(natsorted(qr_list)[y])

            for z in qr_list2:
                qr_image_list2.append(Image.open(z))

            qr_file_count += 1
            image_file = set_grid(qr_image_list2, 3, 3)

            if int(copy) == 1:
                image_file.save(f'{final_qr_path}/QR-File{qr_file_count}.png')
            else:
                if replay == 0:
                    image_file.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
                elif replay > 0:
                    image_file.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay + 1}.png')

            for b in natsorted(qr_list2):
                os.remove(b)

#QR Code Convertion           
def qr_convert(password_list, copy, passp, threshold_number, self):
    global replay
    pass_data = json.dumps(password_list)

    if sys.getsizeof(pass_data) < 1200:

        if os.path.exists(final_qr_path):
            shutil.rmtree(final_qr_path)
            os.mkdir(final_qr_path)
        else:
            os.mkdir(final_qr_path)

        if int(copy) == 1:
            qr_data = { 'Packet_Number': 1, 
                        'QR-Name': 'QR-Code1', 
                        'Data': pass_data  }
            
            #QR Code Convertion
            qr_data_str = json.dumps(qr_data)
            out = io.BytesIO()
            segno.make(qr_data_str, error='h', micro=False).save(out, scale=10, border=7, kind='png')
            out.seek(0)
            img = Image.open(out)

            try:
                font = ImageFont.truetype("Arial.ttf", 65)
                draw = ImageDraw.Draw(img)
                draw.text((0,0), "QR-Code 1", stroke_fill=(255,255,0), font=font)
            except OSError:
                pass

            img.save(f'{final_qr_path}/QR-File1.png')

            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Your passwords are backed up into QR code successfully. The QR codes are stored in "Documents/PassQR". For your security, please delete your QR codes after you printed them.', parent=self)
            kill_command = ["gpgconf", "--kill", "gpg-agent"]
            kill_out = subprocess.check_output(kill_command, universal_newlines=False, shell=False, stderr=subprocess.DEVNULL)

        else:
            passp = passp.encode('latin-1')
            int_val = int.from_bytes(passp, "little")
            ss = shamirs.shares(int_val, quantity=int(copy), modulus=prime, threshold=int(threshold_number))

            for x in range(0, int(copy)):
                
                if x == 0:
                    qr_data = {'Packet_Number': 1, 'QR-Name': 'QR-Code1', 'Data': pass_data, 'Secret': str(ss[x]), 'Threshold': f'{threshold_number}'}
                    dumped = json.dumps(qr_data)

                    out = io.BytesIO()
                    segno.make(dumped, error='h', micro=False).save(out, scale=10, border=7, kind='png')
                    out.seek(0)
                    img = Image.open(out)

                    try:
                        font = ImageFont.truetype("Arial.ttf", 65)
                        draw = ImageDraw.Draw(img)
                        draw.text((0,0), "QR-Code 1", stroke_fill=(255,255,0), font=font)
                    except OSError:
                            pass

                    img.save(f'{final_qr_path}/QR-File1.png')

                else:
                    qr_data = { 'Packet_Number': 1, 
                                'QR-Name': f'QR-Code1-Copy{x + 1}', 
                                'Data': pass_data, 
                                'Secret': str(ss[x]), 
                                'Threshold': f'{threshold_number}'}
                    
                    dumped = json.dumps(qr_data)

                    out = io.BytesIO()
                    segno.make(dumped, error='h', micro=False).save(out, scale=10, border=7, kind='png')
                    out.seek(0)
                    img = Image.open(out)

                    try:
                        font = ImageFont.truetype("Arial.ttf", 65)
                        draw = ImageDraw.Draw(img)
                        draw.text((0,0), f"QR-Code1-Copy{x + 1}", stroke_fill=(255,255,0), font=font)
                    except OSError:
                        pass

                    img.save(f'{final_qr_path}/QR-File1-Copy{x + 1}.png')

            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Your passwords are backed up into QR code successfully. The QR codes are stored in "Documents/PassQR". For your security, please delete your QR codes after you printed them.', parent=self)

            kill_command = ["gpgconf", "--kill", "gpg-agent"]
            kill_out = subprocess.check_output(kill_command, universal_newlines=False, shell=False, stderr=subprocess.DEVNULL)

    else:
        if os.path.exists(final_qr_path):
            shutil.rmtree(final_qr_path)
            os.mkdir(final_qr_path)
        else:
            os.mkdir(final_qr_path)

        if os.path.exists(qr_path):
            shutil.rmtree(qr_path)
            os.mkdir(qr_path)
        else:
            os.mkdir(qr_path)

        if int(copy) == 1:

            #Data Division
            divided_packet = []
            for i in range(0, len(pass_data), 550):
                divided_packet.append(pass_data[i:i+550])
            for index in range(0, len(divided_packet)):

                qr_data = { 'Packet_Number': index + 1, 
                         'QR-Name': f'QR-Code{index + 1}', 
                         'Data': divided_packet[index] }

                dumped = json.dumps(qr_data)

                out = io.BytesIO()
                segno.make(dumped, error='h', micro=False).save(out, scale=10, border=7, kind='png')
                out.seek(0)
                img = Image.open(out)

                try:
                    font = ImageFont.truetype("Arial.ttf", 65)
                    draw = ImageDraw.Draw(img)
                    draw.text((55,0), f"QR-Code {index + 1}", stroke_fill=(255,255,0), font=font)
                except OSError:
                    pass

                img.save(f'{qr_path}/QR{index}.png')
            
            combine_img(copy)
            shutil.rmtree(qr_path)
            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Your passwords are backed up into QR code successfully. The QR codes are stored in "Documents/PassQR". For your security, please delete your QR codes after you printed them.', parent=self)

            kill_command = ["gpgconf", "--kill", "gpg-agent"]
            kill_out = subprocess.check_output(kill_command, universal_newlines=False, shell=False, stderr=subprocess.DEVNULL)

        else:
            global replay
            global qr_file_count
            
            passp = passp.encode('latin-1')
            int_val = int.from_bytes(passp, "little")
            ss = shamirs.shares(int_val, quantity=int(copy), modulus= prime, threshold=int(threshold_number))
            
            for x in range(0, int(copy)):
                divided_packet = []
                if x == 0:
                    for i in range(0, len(pass_data), 550):
                        divided_packet.append(pass_data[i:i+550])
                    for index in range(0, len(divided_packet)):
                        if index == 0:
                            qr_data = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}', 'Data': divided_packet[index], 'Secret': str(ss[x]), 'Threshold': f'{threshold_number}'}
                        else:
                            qr_data = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}', 'Data': divided_packet[index]}

                        dumped = json.dumps(qr_data)

                        out = io.BytesIO()
                        segno.make(dumped, error='h', micro=False).save(out, scale=10, border=7, kind='png')
                        out.seek(0)
                        img = Image.open(out)

                        try:
                            font = ImageFont.truetype("Arial.ttf", 65)
                            draw = ImageDraw.Draw(img)
                            draw.text((0,0), f"QR-Code {index + 1}", stroke_fill=(255,255,0), font=font)
                        except OSError:
                            pass

                        img.save(f'{qr_path}/QR{index}.png')
            
                    combine_img(copy)
                    qr_file_count = 0
                    replay +=1

                else:
                    for i in range(0, len(pass_data), 550):
                        divided_packet.append(pass_data[i:i+550])
                    for index in range(0, len(divided_packet)):
                        if index == 0:

                            qr_data = { 'Packet_Number': index + 1, 
                                     'QR-Name': f'QR-Code{index + 1}-Copy{x + 1}', 
                                     'Data': divided_packet[index], 
                                     'Secret': str(ss[x]), 
                                     'Threshold': f'{threshold_number}' }

                        else:
                            qr_data = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}-Copy{x + 1}', 'Data': divided_packet[index]}

                        dumped = json.dumps(qr_data)

                        out = io.BytesIO()
                        segno.make(dumped, error='h', micro=False).save(out, scale=10, border=7, kind='png')
                        out.seek(0)
                        img = Image.open(out)

                        try:
                            font = ImageFont.truetype("Arial.ttf", 65)
                            draw = ImageDraw.Draw(img)
                            draw.text((0,0), f"QR-Code{index + 1}-Copy{x + 1}", stroke_fill=(255,255,0), font=font)
                        except OSError:
                            pass

                        img.save(f'{qr_path}/QR{index}.png')
            
                    combine_img(copy)
                    qr_file_count = 0
                    replay +=1
                    
            replay = 0
            shutil.rmtree(qr_path)
            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Your passwords are backed up into QR code successfully. The QR codes are stored in "Documents/PassQR". For your security, please delete your QR codes after you printed them.', parent=self)

            kill_command = ["gpgconf", "--kill", "gpg-agent"]
            kill_out = subprocess.check_output(kill_command, universal_newlines=False, shell=False, stderr=subprocess.DEVNULL)

#Symmetric Encryption of Passwords            
def sym_enc(passp, decrypted_password_data, pass_name, copy, threshold, copy_windows, self):
    copy_windows.destroy()
    password_list = []
    for y in range(0, len(pass_name)):
        command2 = ["gpg", "--symmetric", "--cipher-algo", "AES256", "--armor", "--pinentry-mode=loopback", f"--passphrase={passp}"]
        out2 = subprocess.check_output(command2, input=decrypted_password_data[y], universal_newlines=False, shell=False, stderr=subprocess.DEVNULL)
        encode = base64.b64encode(out2)

        password = {f'File{y}':pass_name[y],
                    'cipher': encode.decode('ascii')+"\n"}

        password_list.append(password)
    
    qr_convert(password_list, copy, passp, threshold, self)

def get_threshold_number(re_passp, decrypt_data, pass_name, copy_windows, label2, label3, label4, spin_box, enterbutton, self, exit_button, copy_label, copy_label2, copy_label3):
    copy_number = spin_box.get()
    
    if copy_number == "1":
        copy_windows.destroy()
        threshold_number = 0
        sym_enc(re_passp, decrypt_data, pass_name, copy_number, threshold_number, copy_windows, self)

    else:
        copy_label.destroy()
        copy_label2.destroy()
        copy_label3.destroy()
        copy_windows.geometry("700x185")
        
        label2.configure(text="Minimum Threshold")

        label3.configure(text="As you have more than one copy, you can retreive your passphrase you have created for")
        label3.place(x=50, y=35)

        label3_ct1 = customtkinter.CTkLabel(copy_windows, text="symmetric encryption by combining the first QR code of each copies.")
        label3_ct1.place(x=50, y=58)

        label3_ct2 = customtkinter.CTkLabel(copy_windows, text="Please select a minimum threshold. (Min:2)")
        label3_ct2.place(x=50, y=105)

        label3_ct3 = customtkinter.CTkLabel(copy_windows, text="Minimum threshold is a minimum number of QR codes that is needed to retreive your passphrase.")
        label3_ct3.place(x=50, y=81)

        label4.configure(text="Treshold:")
        label4.place(x=50, y=140)

        current_value = tk.StringVar(value=copy_number)
        spin_box.config(from_=2, to=copy_number, textvariable=current_value)
        spin_box.place(x=125,y=140)
    
        enterbutton.place(x=200,y=140)
        exit_button.place(x=275,y=140)
        enterbutton.configure(command=lambda: sym_enc(re_passp, decrypt_data, pass_name, copy_number, spin_box.get(), copy_windows, self))

def set_copy_number(sym_passp, decrypt_data, pass_name, copy_windows, re_passp_entry, label2, label3, label4, enterbutton, self, exit_button):
    copy_windows.geometry("600x190")
    copy_windows.title("Number of Copies")
    re_passp_entry.destroy()
    label2.configure(text="Number of Copies")

    copy_label = customtkinter.CTkLabel(copy_windows, text="These copies help you to retrieve your passphrase.")
    copy_label.place(x=50,y=35)

    copy_label2 = customtkinter.CTkLabel(copy_windows, text="However, if someone gains access to your copies, it can find out your passphrase.")
    copy_label2.place(x=50,y=60)

    copy_label3 = customtkinter.CTkLabel(copy_windows, text="For your safety, it is recommended to generate only 1 copy.")
    copy_label3.place(x=50,y=85)

    label3.configure(text="How many copies would you like to have? (Min:1, Max:10)")
    label3.place(x=50,y=110)

    label4.configure(text="Copy number:")
    label4.place(x=50,y=140)

    current_value = tk.StringVar(value=1)
    spin_box = tk.Spinbox(copy_windows, from_=1, to=10, textvariable=current_value, width=3, state = 'readonly', wrap=True, bg="black")
    spin_box.place(x=150,y=140)

    enterbutton.configure(command=lambda: get_threshold_number(sym_passp, decrypt_data, pass_name, copy_windows, label2, label3, label4, spin_box, enterbutton, self, exit_button, copy_label, copy_label2, copy_label3))
    enterbutton.place(x=210,y=140)

    exit_button.place(x=285,y=140)

#Passphrase Validation
def check_passps(re_passp_entry, sym_passp, sym_passphrase_windows, decrypt_data, pass_name, label2, label3, label4, enterbutton, self, exit_button):
    if sym_passp == re_passp_entry.get():
        set_copy_number(sym_passp, decrypt_data, pass_name, sym_passphrase_windows, re_passp_entry, label2, label3, label4, enterbutton, self, exit_button)

    else:
        global re_passp_error_count
        global error_count
        re_passp_error_count -= 1
        if re_passp_error_count <= 0:
            sym_passphrase_windows.destroy()
            messagebox.showinfo('', 'Symmetric encryption could not be completed due to incorrent passphrase input.', parent=self)
            main_window.App.enable_button(self)
            error_count = 3
            re_passp_error_count = 3
        else:
            messagebox.showinfo('Bad Passphrase', f'Passphrases do not match (try {re_passp_error_count} out of 3)', parent=sym_passphrase_windows)

def get_sym_entry(sym_passphrase_windows, sym_passp_entry, vcmd, label2, label3, label4, enterbutton ,decrypt_data, pass_name, self, exit_button, label5, label6, label_extra):
    global sym_passp

    special_characters = "!@#$%^&*()-+?_=,<>/"
    alphabet = "abcdefghijklmnopqrstuvwxyz"  
    numbers = "0123456789"
    sym_passp = sym_passp_entry.get()
    if sym_passp:
        if any(c in special_characters or c in numbers for c in sym_passp) and any(c in alphabet.upper() or c in alphabet for c in sym_passp) and len(sym_passp) >=8:
            sym_passphrase_windows.title("New Passphrase Re-Entry for Symmetric Encryption")
            sym_passphrase_windows.geometry("560x150")
            sym_passp_entry.destroy()
            label2.configure(text="New Passphrase Re-Entry for Symmetric Encryption")
            label3.configure(text="Please re-enter your new passphrase")
            label4.place(x=50,y=65)
            label5.destroy()
            label6.destroy()
            label_extra.destroy()
            re_passp_entry = customtkinter.CTkEntry(sym_passphrase_windows, validate="key", validatecommand=vcmd, show="*")
            re_passp_entry.place(x=130,y=65)
            enterbutton.place(x=50,y=100)
            exit_button.place(x=125,y=100)
            enterbutton.configure(command=lambda: check_passps(re_passp_entry, sym_passp, sym_passphrase_windows, decrypt_data, pass_name, label2, label3, label4, enterbutton, self, exit_button))

        else:
            messagebox.showinfo('Weak Passphrase', 'Passphrase you have entered does not meet the requirements.', parent=sym_passphrase_windows)
    else:
        messagebox.showinfo('Empty Passphrase', 'Passphrase should not be empty.', parent=sym_passphrase_windows)

def sym_enc_window(decrypt_data, pass_name, newWindow, passp_entry, enter_button, label2, label3, label4, exit_button, self, label_extra):
    newWindow.title("New Passphrase Entry for Symmetric Encryption")
    newWindow.protocol("WM_DELETE_WINDOW", disable_close)
    newWindow.geometry("530x220")
    passp_entry.destroy()

    label2.configure(text="New Passphrase Entry for Symmetric Encryption")
    label_extra.configure(text="The encrypted versions are stored in your backups.")
    label_extra.place(x=50,y=60)

    label3.configure(text= "Please create a new passphrase to encrypt your passwords.")
    label4.place(x=50,y=140)

    label5 = customtkinter.CTkLabel(newWindow, text ="The passphrase you have entered should be between 8 - 30 characters")
    label5.place(x=50,y=85)

    label6 = customtkinter.CTkLabel(newWindow, text ="long and contain at least 1 digit or special character.")
    label6.place(x=50,y=110)

    def validate(P):
        if len(P) > 30:
            messagebox.showinfo('Passphrase Limit', 'Passphrase should not be longer than 30 characters.', parent=newWindow)
            return False
        elif len(P) <= 30:
            return True

    vcmd = (newWindow.register(validate), '%P')
    sym_passp_entry = customtkinter.CTkEntry(newWindow, validate="key", validatecommand=vcmd, show="*")
    sym_passp_entry.place(x=130,y=140)

    enter_button.place(x=50,y=180)
    exit_button.place(x=125,y=180)
    enter_button.configure(command=lambda: get_sym_entry(newWindow, sym_passp_entry, vcmd, label2, label3, label4, enter_button, decrypt_data, pass_name, self, exit_button, label5, label6, label_extra))

#Asymmetric Decryption
def get_entry(newWindow, passp, pass_files, pass_name, passp_entry, enter_button, label2, label3, label4, exit_button, self, label_extra):
    try:
        check_files = []
        for main_path, sub_directories, files in os.walk(f"{pwd}/.password-store"):
            for name in files:
                if name.endswith('.gpg'):
                    check_file = os.path.join(main_path, name)
                    check_file2 = check_file.replace(".gpg", "")
                    check_files.append(check_file2)
                    
        if (all(x in check_files for x in pass_files)):
            pass
        else:
            raise FileNotFoundError
        
        if passp:
            global decrypted_data
            try:
                for x in range(0, len(pass_files)):
                    command1 = ["gpg", "-d", "--quiet", "--yes", "--pinentry-mode=loopback", f"--passphrase={passp}", f'{pass_files[x]}.gpg']
                    out = subprocess.check_output(command1, universal_newlines=False, shell=False, stderr=subprocess.DEVNULL)
                    decrypted_data.append(out)
                sym_enc_window(decrypted_data, pass_name, newWindow, passp_entry, enter_button, label2, label3, label4, exit_button, self, label_extra)

            except subprocess.CalledProcessError:
                global error_count
                global re_passp_error_count
                error_count -= 1
                if error_count <= 0:
                    newWindow.destroy()
                    messagebox.showinfo('Error Asymmetric Decrypt', 
                                        'Files could not be decrypted due to the incorrect passphrase.', parent=self)
                    error_count = 3
                    re_passp_error_count = 3
                    main_window.App.enable_button(self)
                else:
                    messagebox.showinfo('Bad Passphrase', 
                                        f'Bad passphrase (try {error_count} out of 3)', parent=newWindow)
        else:
            messagebox.showinfo('No Passphrase', 'Passphrase should not be empty.', parent=newWindow)
    except FileNotFoundError:
        newWindow.destroy()
        messagebox.showerror("Error", "An error occurred while decrypting your files. Please check your pass storage and refresh the pass list.", parent=self)
        error_count = 3
        re_passp_error_count = 3
        main_window.App.enable_button(self)

def asym_dec_window(self, pass_files, pass_name):
    newWindow = customtkinter.CTkToplevel(self)
    newWindow.title("Passphrase Entry for Asymmetric Decryption")
    width = 500
    height = 170
    
    screen_width = self.winfo_screenwidth()
    screen_height = self.winfo_screenheight()
    
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)

    newWindow.geometry('%dx%d+%d+%d' % (width, height, x, y))
    newWindow.resizable(False,False)
    newWindow.protocol("WM_DELETE_WINDOW", disable_close)

    label2 = customtkinter.CTkLabel(newWindow, text="Passphrase Entry for Asymmetric Decryption", font=customtkinter.CTkFont(size=20, weight="bold"))
    label2.place(x=50,y=10)

    label3 = customtkinter.CTkLabel(newWindow,text ="Your passwords are assymetrically encrypted inside the pass storage.")
    label3.place(x=50,y=35)

    label_extra = customtkinter.CTkLabel(newWindow,text ="Please enter your existing passphrase to decrypt your passwords.")
    label_extra.place(x=50,y=60)

    label4 = customtkinter.CTkLabel(newWindow,text ="Passphrase:")
    label4.place(x=50,y=90)
    
    passp_entry = customtkinter.CTkEntry(newWindow, show="*")
    passp_entry.place(x=130,y=90)

    enter_button = customtkinter.CTkButton(newWindow, text='Enter', command=lambda: get_entry(newWindow, passp_entry.get(), pass_files, pass_name, passp_entry, enter_button, label2, label3, label4, exit_button, self, label_extra), fg_color="darkred", hover_color="#D2042D", width=60)
    enter_button.place(x=50,y=125)

    exit_button = customtkinter.CTkButton(newWindow, text="Cancel Backup", command=lambda: cancel_convert(self, newWindow), fg_color="darkred", hover_color="#D2042D")
    exit_button.place(x=125,y=125)

#References
#set_grid function is from: https://stackoverflow.com/questions/37921295/python-pil-image-make-3x3-grid-from-sequence-images
#Lines 476, 503, 588, 587, 686, and 671 are implemented with the help of https://stackoverflow.com/questions/75480143/python-tkinter-removing-nested-functions. Oguz Gokyuzu is my username.
#Lines 428-429, 609-610 are implemented with the help of: https://stackoverflow.com/questions/75400145/gpg-does-not-accept-passphrase-that-begins-with-some-special-characters. Oguz Gokyuzu is my username.
#Moreover, Lines 428-429 and 609-610 are also from: https://stackoverflow.com/questions/60860285/python-symmetric-encryption-with-gpg-and-subprocess
