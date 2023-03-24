import os
import sys
import json
import shutil
import qrcode
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

pwd = os.path.expanduser('~')
qr_path = f"{pwd}/Documents/.QR-Code"
final_qr_path = f'{pwd}/Documents/Pass-QRCode'

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
        error_count = 3
        re_passp_error_count = 3
        window.destroy()
        main_window.App.enable_button(self)

def image_grid(imgs, rows, cols):

    len(imgs) == rows*cols

    w, h = imgs[0].size
    grid = Image.new('RGB', (cols*w, rows*h), (255,255,255))
    grid_w, grid_h = grid.size
    
    for i, img in enumerate(imgs):
        grid.paste(img, box=(i%cols*w, i//cols*h))
    return grid

def combine_img():
    global replay
    qr_file_count = 0

    if os.path.exists(final_qr_path):
        pass
    else:
        os.mkdir(final_qr_path)

    if replay == 0:
        original_dir = f"{final_qr_path}/Original"

        if os.path.exists(original_dir):
            shutil.rmtree(original_dir)
            os.mkdir(original_dir)
        else:
            os.mkdir(original_dir)

    else: 
        copy_dir = f"{final_qr_path}/Copy-{replay}"

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
        
        for path, subdirs, files in os.walk(qr_path):
            for name in files:
                if name.endswith('.png'):
                    joined = os.path.join(path, name)
                    qr_list.append(joined)

        for x in natsorted(qr_list):
            qr_image_list.append(Image.open(x))

        if len(qr_image_list) == 1:
            qr_file_count += 1
            grid = image_grid(qr_image_list, 1, 1)
            if replay == 0:
                grid.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
            elif replay > 0:
                grid.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay}.png')
            return False

        elif len(qr_image_list) == 2:
            qr_file_count += 1
            grid = image_grid(qr_image_list, 1, 2)
            if replay == 0:
                grid.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
            elif replay > 0:
                grid.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay}.png')
            return False

        elif len(qr_image_list) == 3 or len(qr_image_list) == 4:
            qr_file_count += 1
            grid = image_grid(qr_image_list, 2, 2)
            if replay == 0:
                grid.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
            elif replay > 0:
                grid.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay}.png')
            return False

        elif len(qr_image_list) == 5 or len(qr_image_list) == 6:
            qr_file_count += 1
            grid = image_grid(qr_image_list, 2, 3)
            if replay == 0:
                grid.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
            elif replay > 0:
                grid.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay}.png')
            return False

        elif len(qr_image_list) == 7 or len(qr_image_list) == 8 or len(qr_image_list) == 9:
            qr_file_count += 1
            grid = image_grid(qr_image_list, 3, 3)
            if replay == 0:
                grid.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
            elif replay > 0:
                grid.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay}.png')
            return False

        elif len(qr_image_list) >= 9:
            
            for y in range(0,9):
                qr_list2.append(natsorted(qr_list)[y])

            for z in qr_list2:
                qr_image_list2.append(Image.open(z))

            qr_file_count += 1
            grid = image_grid(qr_image_list2, 3, 3)

            if replay == 0:
                grid.save(f'{original_dir}/QR-File{qr_file_count}.png')
            
            elif replay > 0:
                grid.save(f'{copy_dir}/QR-File{qr_file_count}-Copy{replay}.png')

            for b in natsorted(qr_list2):
                os.remove(b)
            
def qr_convert(json_list, copy, passp, threshold_number, self):
    global replay
    dump = json.dumps(json_list)

    if sys.getsizeof(dump) < 2000:

        if os.path.exists(final_qr_path):
            shutil.rmtree(final_qr_path)
            os.mkdir(final_qr_path)
        else:
            os.mkdir(final_qr_path)

        if int(copy) == 1:
            json1 = {'Packet_Number': '1', 'QR-Name': 'QR-Code1', 'Data': dump}
            dumped = json.dumps(json1)
            qr = qrcode.QRCode(version=1, box_size=10, border=7)
            qr.add_data(dumped)
            qr.make(fit=True)
            img = qr.make_image()
            font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 65)
            draw = ImageDraw.Draw(img)
            draw.text((0,0), "QR-Code 1", stroke_fill=(255,255,0), font=font)

            img.save(f'{final_qr_path}/QR-File1.png')

            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Pass files converted to QR code successfully')
            
        else:
            passp = passp.encode('latin-1')
            int_val = int.from_bytes(passp, "little")
            ss = shamirs.shares(int_val, quantity=int(copy), modulus=prime, threshold=int(threshold_number))

            for x in range(0, int(copy)):
                
                if x == 0:
                    json1 = {'Packet_Number': '1', 'QR-Name': 'QR-Code1', 'Data': dump, 'Secret': str(ss[x]), 'Threshold': f'{threshold_number}'}
                    dumped = json.dumps(json1)
                    qr = qrcode.QRCode(version=1, box_size=10, border=7)
                    qr.add_data(dumped)
                    qr.make(fit=True)
                    img = qr.make_image()
                    font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 65)
                    draw = ImageDraw.Draw(img)
                    draw.text((0,0), "QR-Code 1", stroke_fill=(255,255,0), font=font)
                    img.save(f'{final_qr_path}/QR-File1.png')

                else:
                    json1 = {'Packet_Number': '1', 'QR-Name': f'QR-Code1-Copy{x}', 'Data': dump, 'Secret': str(ss[x]), 'Threshold': f'{threshold_number}'}
                    dumped = json.dumps(json1)
                    qr = qrcode.QRCode(version=1, box_size=10, border=7)
                    qr.add_data(dumped)
                    qr.make(fit=True)
                    img = qr.make_image()
                    font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 65)
                    draw = ImageDraw.Draw(img)
                    draw.text((0,0), "QR-Code 1", stroke_fill=(255,255,0), font=font)
                    img.save(f'{final_qr_path}/QR-File1-Copy{x}.png')

            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Pass files converted to QR code successfully')

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
            packet2 = []
            for i in range(0, len(dump), 750):
                packet2.append(dump[i:i+750])
            for index in range(0, len(packet2)):
                json1 = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}', 'Data': packet2[index]}

                dumped = json.dumps(json1)

                qr = qrcode.QRCode(version=1, box_size=10, border=7)
                qr.add_data(dumped)
                qr.make(fit=True)
                img = qr.make_image()
                
                font = ImageFont.truetype("Arial.ttf", 65)
                draw = ImageDraw.Draw(img)
                draw.text((55,0), f"QR-Code {index + 1}", stroke_fill=(255,255,0), font=font)

                img.save(f'{qr_path}/QR{index}.png')
            
            combine_img()
            shutil.rmtree(qr_path)
            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Pass files converted to QR code successfully')

        else:
            global replay
            global qr_file_count

            passp = passp.encode('latin-1')
            int_val = int.from_bytes(passp, "little")
            ss = shamirs.shares(int_val, quantity=int(copy), modulus= prime, threshold=int(threshold_number))
            
            for x in range(0, int(copy)):
                packet2 = []
                if x == 0:
                    for i in range(0, len(dump), 750):
                        packet2.append(dump[i:i+750])
                    for index in range(0, len(packet2)):
                        if index == 0:
                            json1 = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}', 'Data': packet2[index], 'Secret': str(ss[x]), 'Threshold': f'{threshold_number}'}
                        else:
                            json1 = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}', 'Data': packet2[index]}

                        dumped = json.dumps(json1)

                        qr = qrcode.QRCode(version=1, box_size=10, border=7)
                        qr.add_data(dumped)
                        qr.make(fit=True)
                        img = qr.make_image()
                        font = ImageFont.truetype("Arial.ttf", 65)
                        draw = ImageDraw.Draw(img)
                        draw.text((0,0), f"QR-Code {index + 1}", stroke_fill=(255,255,0), font=font)

                        img.save(f'{qr_path}/QR{index}.png')
            
                    combine_img()
                    qr_file_count = 0
                    replay +=1

                else:
                    for i in range(0, len(dump), 750):
                        packet2.append(dump[i:i+750])
                    for index in range(0, len(packet2)):
                        if index == 0:
                            json1 = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}-Copy{x}', 'Data': packet2[index], 'Secret': str(ss[x]), 'Threshold': f'{threshold_number}'}
                        else:
                            json1 = {'Packet_Number': index + 1, 'QR-Name': f'QR-Code{index + 1}-Copy{x}', 'Data': packet2[index]}

                        dumped = json.dumps(json1)

                        qr = qrcode.QRCode(version=1, box_size=10, border=7)
                        qr.add_data(dumped)
                        qr.make(fit=True)
                        img = qr.make_image()
                        font = ImageFont.truetype("Arial.ttf", 65)
                        draw = ImageDraw.Draw(img)
                        draw.text((0,0), f"QR-Code {index + 1}", stroke_fill=(255,255,0), font=font)

                        img.save(f'{qr_path}/QR{index}.png')
            
                    combine_img()
                    qr_file_count = 0
                    replay +=1
                    
            replay = 0
            shutil.rmtree(qr_path)
            main_window.App.enable_button(self)
            messagebox.showinfo('Success', 'Pass files converted to QR code successfully')

def sym_enc(passp, decrypt_data, files, copy, threshold, copy_windows, self):
    copy_windows.destroy()
    json_list = []
    for y in range(0, len(files)):
        command2 = ["gpg", "--symmetric", "--armor", "--pinentry-mode=loopback", f"--passphrase={passp}"]
        out2 = subprocess.check_output(command2, input=decrypt_data[y], universal_newlines=False)
        encode = base64.b64encode(out2)
        json_file = {f'File{y}':files[y], 'cipher': encode.decode('ascii')+"\n"}
        json_list.append(json_file)
    
    qr_convert(json_list, copy, passp, threshold, self)

def get_copy_number(re_passp, decrypt_data, files, copy_windows, label2, label3, label4, spin_box, enterbutton, self, exit_button):
    copy_number = spin_box.get()
    
    if copy_number == "1":
        copy_windows.destroy()
        threshold_number = 0
        sym_enc(re_passp, decrypt_data, files, copy_number, threshold_number, copy_windows, self)

    else:
        copy_windows.geometry("700x170")
        label2.configure(text="Minimum Threshold")
        label3.configure(text="As you have more than one copy, you can retreive your passphrase you have created for")
        label3.place(x=50, y=35)
        label3_ct1 = customtkinter.CTkLabel(copy_windows, text="symmetric encryption by combining the first QR code of each copies.")
        label3_ct1.place(x=50, y=55)
        label3_ct2 = customtkinter.CTkLabel(copy_windows, text="Please select a minimum threshold. (Min:2)")
        label3_ct2.place(x=50, y=95)
        label3_ct3 = customtkinter.CTkLabel(copy_windows, text="Minimum threshold is a minimum number of QR codes that is needed to retreive your passphrase.")
        label3_ct3.place(x=50, y=75)
        label4.configure(text="Treshold:")
        label4.place(x=50, y=125)

        current_value = tk.StringVar(value=copy_number)
        spin_box.config(from_=2, to=copy_number, textvariable=current_value)
        spin_box.place(x=125,y=125)
    
        enterbutton.place(x=200,y=125)
        exit_button.place(x=275,y=125)
        enterbutton.configure(command=lambda: sym_enc(re_passp, decrypt_data, files, copy_number, spin_box.get(), copy_windows, self))

def set_copy_number(re_passp, decrypt_data, files, sym_passphrase_windows, re_passp_entry, label2, label3, label4, enterbutton, self, exit_button):
    sym_passphrase_windows.geometry("500x150")
    sym_passphrase_windows.title("Number of Copies")
    re_passp_entry.destroy()
    label2.configure(text="Number of Copies")
    label3.configure(text="How many copies would you like to have? (Min:1, Max:10)")
    label4.configure(text="Copy number:")

    current_value = tk.StringVar(value=1)
    spin_box = tk.Spinbox(sym_passphrase_windows, from_=1, to=10, textvariable=current_value, width=3, state = 'readonly', wrap=True, bg="black")
    spin_box.place(x=150,y=65)

    enterbutton.configure(command=lambda: get_copy_number(re_passp, decrypt_data, files, sym_passphrase_windows, label2, label3, label4, spin_box, enterbutton, self, exit_button))

def check_passps(re_passp_entry, sym_passp, sym_passphrase_windows, decrypt_data, files, label2, label3, label4, enterbutton, self, exit_button):
    re_passp = re_passp_entry.get()
    if sym_passp == re_passp:
        set_copy_number(re_passp, decrypt_data, files, sym_passphrase_windows, re_passp_entry, label2, label3, label4, enterbutton, self, exit_button)

    else:
        global re_passp_error_count
        global error_count
        re_passp_error_count -= 1
        if re_passp_error_count <= 0:
            sym_passphrase_windows.destroy()
            messagebox.showinfo('', 'Symmetric encryption could not be completed due to incorrent passphrase input.')
            main_window.App.enable_button(self)
            error_count = 3
            re_passp_error_count = 3
        else:
            messagebox.showinfo('Bad Passphrase', f'Passphrases do not match (try {re_passp_error_count} out of 3)', parent=sym_passphrase_windows)

def get_sym_entry(sym_passphrase_windows, sym_passp_entry, vcmd, label2, label3, label4, enterbutton ,decrypt_data, files, self, exit_button):
    special_characters = "!@#$%^&*()-+?_=,<>/"
    alphabet = "abcdefghijklmnopqrstuvwxyz"  
    numbers = "0123456789"
    sym_passp = sym_passp_entry.get()

    if any(c in special_characters or c in numbers for c in sym_passp) and any(c in alphabet.upper() or c in alphabet for c in sym_passp) and len(sym_passp) >=8:
        sym_passp_entry.destroy()
        label3.configure(text="Please re-enter your new passphrase")
        re_passp_entry = customtkinter.CTkEntry(sym_passphrase_windows, validate="key", validatecommand=vcmd, show="*")
        re_passp_entry.place(x=130,y=65)
        enterbutton.configure(command=lambda: check_passps(re_passp_entry, sym_passp, sym_passphrase_windows, decrypt_data, files, label2, label3, label4, enterbutton, self, exit_button))

    else:
        if messagebox.askyesno('Weak Passphrase', 'Your passphrase is not considered strong. Do you wish to use this one?', parent=sym_passphrase_windows):
            sym_passp_entry.destroy()
            label3.configure(text="Please re-enter your new passphrase")
            re_passp_entry = customtkinter.CTkEntry(sym_passphrase_windows, validate="key", validatecommand=vcmd, show="*")
            re_passp_entry.place(x=130,y=65)
            enterbutton.configure(command=lambda: check_passps(re_passp_entry, sym_passp, sym_passphrase_windows, decrypt_data, files, label2, label3, label4, enterbutton, self, exit_button))

def sym_enc_window(decrypt_data, files, newWindow, passp_entry, enter_button, label2, label3, label4, exit_button, self):
    newWindow.title("Passphrase for Symmetric Encryption")
    newWindow.protocol("WM_DELETE_WINDOW", disable_close)

    passp_entry.destroy()

    label2.configure(text="Passphrase for Symmetric Encryption")
    label3.configure(text= "Please create a new passphrase for encryption.")

    def validate(P):
        if len(P) > 30:
            messagebox.showinfo('Passphrase Limit', 'Passphrase should not be longer than 30 characters.', parent=newWindow)
            return False
        elif len(P) <= 30:
            return True

    vcmd = (newWindow.register(validate), '%P')
    sym_passp_entry = customtkinter.CTkEntry(newWindow, validate="key", validatecommand=vcmd, show="*")
    sym_passp_entry.place(x=130,y=65)

    enter_button.configure(command=lambda: get_sym_entry(newWindow, sym_passp_entry, vcmd, label2, label3, label4, enter_button, decrypt_data, files, self, exit_button))

def get_entry(newWindow, passp, pass_files, files, passp_entry, enter_button, label2, label3, label4, exit_button, self):
    if passp:
        decrypted_data = []
        try:
            for x in range(0, len(pass_files)):
                command1 = ["gpg", "-d", "--quiet", "--yes", "--pinentry-mode=loopback", f"--passphrase={passp}", f'{pass_files[x]}.gpg']
                out = subprocess.check_output(command1, universal_newlines=False)
                decrypted_data.append(out)
            sym_enc_window(decrypted_data, files, newWindow, passp_entry, enter_button, label2, label3, label4, exit_button, self)

        except subprocess.CalledProcessError:
            global error_count
            global re_passp_error_count
            error_count -= 1
            if error_count <= 0:
                newWindow.destroy()
                messagebox.showinfo('Error Asymmetric Decrypt', 'Files could not be decrypted due to the incorrect passphrase.')
                error_count = 3
                re_passp_error_count = 3
                main_window.App.enable_button(self)
            else:
                messagebox.showinfo('Bad Passphrase', f'Bad passphrase (try {error_count} out of 3)', parent=newWindow)

def asym_dec_window(self, pass_files, files):
    newWindow = customtkinter.CTkToplevel(self)
    newWindow.title("Passphrase for Asymmetric Decryption")
    newWindow.geometry("500x150")
    newWindow.resizable(False,False)
    newWindow.protocol("WM_DELETE_WINDOW", disable_close)

    label2 = customtkinter.CTkLabel(newWindow, text="Passphrase for Asymmetric Decryption", font=customtkinter.CTkFont(size=20, weight="bold"))
    label2.place(x=50,y=10)

    label3 = customtkinter.CTkLabel(newWindow,text ="Please put your passphrase for decryption.")
    label3.place(x=50,y=35)

    label4 = customtkinter.CTkLabel(newWindow,text ="Passphrase:")
    label4.place(x=50,y=65)
    
    passp_entry = customtkinter.CTkEntry(newWindow, show="*")
    passp_entry.place(x=130,y=65)

    enter_button = customtkinter.CTkButton(newWindow, text='Enter', command=lambda: get_entry(newWindow, passp_entry.get(), pass_files, files, passp_entry, enter_button, label2, label3, label4, exit_button, self), fg_color="darkred", hover_color="#D2042D", width=60)
    enter_button.place(x=50,y=100)

    exit_button = customtkinter.CTkButton(newWindow, text="Cancel Convert", command=lambda: cancel_convert(self, newWindow), fg_color="darkred", hover_color="#D2042D")
    exit_button.place(x=125,y=100)