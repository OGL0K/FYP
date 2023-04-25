import os
import re
import cv2
import time
import json
import gnupg
import shutil
import base64
import shamirs
import subprocess
import main_window
import numpy as np
import customtkinter
import tkinter as tk
import pyzbar.pyzbar as pyzbar

from shamirs import share
from natsort import natsorted
from PIL import Image, ImageTk
from tkinter import messagebox

#Global Variables
pwd = os.path.expanduser('~')
password_store = f"{pwd}/.password-store"
password_store_gpg_id = f"{pwd}/.password-store/.gpg-id"

passphrase = ""
error_count = 3
re_passp_error_count = 3

def disable_close():
    pass

def exit_gen_gpg_passp(self, window):
    if messagebox.askyesno('Cancel Generation', 'Are you sure to cancel your generation process?', parent=window):
        global passphrase
        passphrase = ""
        window.destroy()
        main_window.App.enable_button(self)

def exit_scan(self, scanWindow, camera, scanned_values):
    if messagebox.askyesno('Exit Scan', 'Are you sure to exit scanning and cancel all your process?', parent=scanWindow):
        scanned_values == []
        camera.release()        
        cv2.waitKey(1)
        cv2.destroyAllWindows()
        scanWindow.destroy()
        main_window.App.enable_button(self)

def check_passp_and_import(self, final_json, passp_entry, passp_window):
    global error_count
    passp = passp_entry.get()
    
    try:
        try:
            decrypted_password_data = []
            for i in range(0, len(final_json)):
                decoded_data = base64.b64decode(final_json[i]["cipher"])
                command1 = ["gpg", "-d", "--quiet", "--pinentry-mode=loopback", f"--passphrase={passp}"]
                out1 = subprocess.check_output(command1, input=decoded_data, universal_newlines=False, shell=False)
                decrypted_password_data.append(out1)

        except subprocess.CalledProcessError:
        
                global error_count
                error_count -= 1
                if error_count <= 0:
                    messagebox.showinfo('Error Asymmetric Decrypt', 'Files could not be decrypted due to the incorrect passphrase.', parent=passp_window)
                    passp_window.destroy()
                    main_window.App.enable_button(self)
                    error_count = 3
                else:
                    messagebox.showinfo('Bad Passphrase', f'Bad passphrase (try {error_count} out of 3)', parent=passp_window)

        with open(f'{password_store_gpg_id}', 'r') as id_file:
            gpg_key = str(id_file.read()).strip()
        
        for i in range(0, len(final_json)):
                os.makedirs(os.path.dirname(f'{password_store}/{final_json[i][f"File{i}"]}'), exist_ok=True)
                command2 = ["gpg", "--batch", "--quiet", "--yes", "--encrypt", "-r", gpg_key, "-o" ,f"{password_store}/{final_json[i][f'File{i}']}.gpg"]
                out2 = subprocess.check_output(command2, input=decrypted_password_data[i], universal_newlines=False, shell=False)

        decrypted_password_data.clear()
        passp_window.destroy()
        messagebox.showinfo('Success', 'Your passwords have been imported to the pass store successfully.', parent=self)
        main_window.App.refresh(self)
        main_window.App.enable_button(self)
        
    except IndexError:
        pass
    except UnboundLocalError:
        pass

def get_passp(self, final_json, scanWindow, camera):
    camera.release()        
    cv2.waitKey(1)
    cv2.destroyAllWindows()
    scanWindow.destroy()

    passp_window = customtkinter.CTkToplevel(self)
    passp_window.title("Passphrase for Symmetric Decryption")
    passp_window.geometry("500x150")
    passp_window.resizable(False,False)
    passp_window.protocol("WM_DELETE_WINDOW", disable_close)

    passp_label2 = customtkinter.CTkLabel(passp_window, text="Passphrase for Symmetric Decryption", font=customtkinter.CTkFont(size=20, weight="bold"))
    passp_label2.place(x=50,y=10)

    passp_label3 = customtkinter.CTkLabel(passp_window,text ="Please put your passphrase for decryption.")
    passp_label3.place(x=50,y=35)

    passp_label4 = customtkinter.CTkLabel(passp_window,text ="Passphrase:")
    passp_label4.place(x=50,y=65)

    passp_entry = customtkinter.CTkEntry(passp_window, show="*")
    passp_entry.place(x=130,y=65)

    enter_button = customtkinter.CTkButton(passp_window, text='Enter', command=lambda: check_passp_and_import(self, final_json, passp_entry, passp_window), fg_color="darkred", hover_color="#D2042D", width=60)
    enter_button.place(x=50,y=100)

def evaluate_packets(self, scanWindow, camera, scanned_values):
    try:
        json_list1 = []
        sort_scanned_values = natsorted(scanned_values)

        for x in range(0, len(sort_scanned_values)):
            a = json.loads(sort_scanned_values[x])
            json_list1.append(a)

        data_string = ""
        for index in range(0, len(json_list1)):
            data_string += json_list1[index]['Data']

        final_json = json.loads(data_string)
        get_passp(self, final_json, scanWindow, camera)
    
    except json.decoder.JSONDecodeError:
        messagebox.showinfo('Error', 'There was a problem while processing your data. Please check the QR codes you have scanned.', parent=scanWindow)

def delete_QR_code(status_label, continue_button, scanned_packets_listbox, scanned_values):
    if len(scanned_values) == 0:
            status_label.configure(text="Error: Scanned QR Code List is empty.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
            status_label.place(x=20, y=13)
    else:
        continue_button.place_forget()
        scanned_values.clear()
        status_label.configure(text="Scanned QR Code List has been deleted successfully.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="green")
        scanned_packets_listbox.delete(0, tk.END)

def scan_qr_start(self):
    if os.path.exists(password_store):
        pass
    else:
        messagebox.showinfo('No Pass Repository', 'There is no pass repository located on your machine. In order to use this feature please create a pass repository by clicking "Generate GPG Key & Pass Storage" button.', parent=self)
        return None

    if messagebox.askyesno('Scan QR', 'Are you sure to scan your QR code(s) and importing its values to your pass repository?', parent=self):

        #Connecting to the Computer Camera
        try:
            camera = cv2.VideoCapture(0)
            camera.set(3, 640)
            camera.set(4, 480)
            if camera is None or not camera.isOpened():
                raise ConnectionError
            
        except ConnectionError:
            messagebox.showerror('Error','Could not find any camera.', parent=self)
        
        else: 
            scanned_values = []
            main_window.App.disable_button(self)
            scanWindow = customtkinter.CTkToplevel(self)
            scanWindow.title("Recover Passwords")
            scanWindow.geometry("870x550")
            scanWindow.resizable(False,False)
            scanWindow.protocol("WM_DELETE_WINDOW", disable_close)

            frame=np.random.randint(0,255,[100,100,3],dtype='uint8')

            scanlabel = tk.Label(scanWindow)
            scanlabel.place(x=0, y=0)

            sidebar_frame1 = customtkinter.CTkFrame(scanWindow, width=230, height=700, corner_radius=0)
            sidebar_frame1.place(x=640, y=0)

            scanned_packets_label = customtkinter.CTkLabel(sidebar_frame1, text= "Scanned QR Code List", font=customtkinter.CTkFont(size=14, weight="bold"))
            scanned_packets_label.place(x=35, y=5)

            scanned_packets_listbox = tk.Listbox(sidebar_frame1, selectmode=tk.BROWSE, height=20, width=22)
            scanned_packets_listbox.place(x=15, y=40)

            status_frame = customtkinter.CTkFrame(scanWindow, width=620, height=55, corner_radius=15)
            status_frame.place(x=10, y=490)

            status_label = customtkinter.CTkLabel(status_frame, text="Please scan your QR code on the camera above.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="white")
            status_label.place(x=20, y=13)

            delete_QR_button = customtkinter.CTkButton(sidebar_frame1, text='Delete List' ,command=lambda: delete_QR_code(status_label, continue_button, scanned_packets_listbox, scanned_values),  fg_color="darkred", hover_color="#D2042D")
            delete_QR_button.place(x=48, y=400)

            continue_button = customtkinter.CTkButton(sidebar_frame1, text='Import', command=lambda: evaluate_packets(self, scanWindow, camera, scanned_values),  fg_color="darkred", hover_color="#D2042D")

            scan_exit = customtkinter.CTkButton(sidebar_frame1, text='Exit Scan', command=lambda: exit_scan(self, scanWindow, camera, scanned_values),  fg_color="darkred", hover_color="#D2042D")
            scan_exit.place(x=48, y=500)
            
            #QR Code Detection and Scan
            while True:
                try: 
                    _, frame = camera.read()
                    scanned_qr_data = pyzbar.decode(frame)
                    
                    for i in scanned_qr_data:
                        pnt = i.polygon
                        points = np.array(pnt, np.int32)
                        points = points.reshape(-1,1,2)
                        cv2.polylines(frame, [points], True, (255,0,255), 5)
                    
                    frame=cv2.cvtColor(frame,cv2.COLOR_BGR2RGB)
                    image_update = ImageTk.PhotoImage(Image.fromarray(frame))
                    scanlabel.configure(image=image_update)
                    scanlabel.image=image_update
                    scanlabel.update()

                    if scanned_qr_data[0].data.decode('ascii') not in scanned_values:
                        array = []
                        convert_package = json.loads(scanned_qr_data[0].data.decode('ascii'))
                        scanned_packets_listbox.insert(0, convert_package['QR-Name'])
                        
                        if scanned_packets_listbox.size() <= 1:
                            pass

                        else:
                            for i in range(0, scanned_packets_listbox.size()):
                                op = scanned_packets_listbox.get(i)
                                array.append(op)
                            sorted_array = natsorted(array)
                            scanned_packets_listbox.delete(0, tk.END)

                            for y in range(0, len(sorted_array)):
                                scanned_packets_listbox.insert(y, sorted_array[y])

                        scanned_values.append(scanned_qr_data[0].data.decode('ascii'))
                        status_label.configure(text=f"{convert_package['QR-Name']} has been scanned successfully.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="green")
                        status_label.place(x=20, y=13)
                        continue_button.place(x=48, y=440)
                        time.sleep(1.5)

                    elif scanned_qr_data[0].data.decode('ascii') in scanned_values:
                        convert_package = json.loads(scanned_qr_data[0].data.decode('ascii'))
                        status_label.configure(text=f"Error: {convert_package['QR-Name']} has been already scanned.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
                        status_label.place(x=20, y=13)
                        time.sleep(1.5)
                
                except json.decoder.JSONDecodeError:
                    status_label.configure(text=f"Error: Invalid QR Code has been scanned.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
                    status_label.place(x=20, y=13)
                    time.sleep(1.5)

                except KeyError:
                    status_label.configure(text=f"Error: Invalid QR Code has been scanned.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
                    status_label.place(x=20, y=13)
                    time.sleep(1.5)

                except tk.TclError:    
                    pass

                except IndexError:
                    pass
                
                except TypeError:
                    break

def complete_shamir(self, shamirWindow, camera, shamir_scan_values):
    try:
        if messagebox.askyesno('Are you sure?', 'Do you want to retrieve your passphrase? Please click yes if you are sure that no one can see your screen.', parent=shamirWindow):
            shamir_list = []
            for y in range(0, len(shamir_scan_values)):
                load2 = json.loads(shamir_scan_values[y])
                shamir_list.append(load2)
            
            threshold_list = [] 
            for x in range(0, len(shamir_list)):
                threshold_list.append(shamir_list[x]['Threshold'])

            result = threshold_list.count(threshold_list[0]) == len(threshold_list)

            if (result):

                #Passphrase Share Combination
                secret_list = []
                for z in range(0, len(shamir_list)):
                    conv = eval(shamir_list[z]['Secret'])
                    secret_list.append(conv)
                
                passp_recover = shamirs.interpolate(secret_list, threshold=int(threshold_list[0]))
                passp_recover = passp_recover.to_bytes(len(str(passp_recover)), 'little')
                passp_recover = passp_recover.decode('latin-1')

                camera.release()        
                cv2.waitKey(1)
                cv2.destroyAllWindows()
                shamirWindow.destroy()
                shamir_scan_values = []
                main_window.App.enable_button(self)
                messagebox.showinfo('Success', f'Your passphrase is: {passp_recover}', parent=self)
                passp_recover = ""

            else:
                messagebox.showinfo('Error','There was a problem while retrieving your passphrase. Please check the QR codes you have scanned.', parent=shamirWindow)

    except ValueError:
        messagebox.showinfo('Error','The number of QR codes you have scanned does not meet the minimum threshold.', parent=shamirWindow)

def delete_shamir_value(status_label, continue_button, shamir_scan_values, scanned_shamir_listbox):
    if len(shamir_scan_values) == 0:
            status_label.configure(text="Error: Scanned QR Code List is empty.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
            status_label.place(x=20, y=13)
    else:
        continue_button.place_forget()
        shamir_scan_values.clear()
        status_label.configure(text="Scanned QR Code List has been deleted successfully.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="green")
        scanned_shamir_listbox.delete(0, tk.END)

def shamir_scan_start(self):
    if messagebox.askyesno('Scan QR', 'Are you sure to retreive your passphrase?', parent=self):
        try:
            camera = cv2.VideoCapture(0)
            camera.set(3, 640)
            camera.set(4, 480)
            if camera is None or not camera.isOpened():
                raise ConnectionError
            
        except ConnectionError:
            messagebox.showerror('Error','Could not find any camera.', parent=self) 
        
        else: 
            shamir_scan_values = []
            main_window.App.disable_button(self)
            shamirWindow = customtkinter.CTkToplevel(self)
            shamirWindow.title("Retrieve Passphrase")
            shamirWindow.geometry("870x550")
            shamirWindow.resizable(False,False)
            shamirWindow.protocol("WM_DELETE_WINDOW", disable_close)

            frame=np.random.randint(0,255,[100,100,3],dtype='uint8')

            scanlabel = tk.Label(shamirWindow)
            scanlabel.place(x=0, y=0)

            sidebar_frame2 = customtkinter.CTkFrame(shamirWindow, width=230, height=700, corner_radius=0)
            sidebar_frame2.place(x=640, y=0)

            scanned_shamir_label = customtkinter.CTkLabel(sidebar_frame2, text= "Scanned QR Code List", font=customtkinter.CTkFont(size=14, weight="bold"))
            scanned_shamir_label.place(x=35, y=5)

            scanned_shamir_listbox = tk.Listbox(sidebar_frame2, selectmode=tk.BROWSE, height=20, width=22)
            scanned_shamir_listbox.place(x=15, y=40)

            status_frame = customtkinter.CTkFrame(shamirWindow, width=620, height=55, corner_radius=15)
            status_frame.place(x=10, y=490)

            status_label = customtkinter.CTkLabel(status_frame, text="Please scan the first QR code of each copy.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="white")
            status_label.place(x=20, y=13)

            delete_QR_button = customtkinter.CTkButton(sidebar_frame2, text='Delete List' ,command=lambda: delete_shamir_value(status_label, continue_button, shamir_scan_values, scanned_shamir_listbox),  fg_color="darkred", hover_color="#D2042D")
            delete_QR_button.place(x=48, y=400)

            continue_button = customtkinter.CTkButton(sidebar_frame2, text='Retrieve', command=lambda: complete_shamir(self, shamirWindow, camera, shamir_scan_values),  fg_color="darkred", hover_color="#D2042D")

            scan_exit = customtkinter.CTkButton(sidebar_frame2, text='Exit Scan', command=lambda: exit_scan(self, shamirWindow, camera, shamir_scan_values),  fg_color="darkred", hover_color="#D2042D")
            scan_exit.place(x=48, y=500)
        
            while True:
                try: 
                    _, frame = camera.read()
                    scanned_qr_data = pyzbar.decode(frame)
                    
                    for i in scanned_qr_data:
                        pnt = i.polygon
                        points = np.array(pnt, np.int32)
                        points = points.reshape(-1,1,2)
                        cv2.polylines(frame, [points], True, (50,205,50), 5)

                    frame=cv2.cvtColor(frame,cv2.COLOR_BGR2RGB)
                    image_update = ImageTk.PhotoImage(Image.fromarray(frame))
                    scanlabel.configure(image=image_update)
                    scanlabel.image=image_update
                    scanlabel.update()

                    if scanned_qr_data[0].data.decode('ascii')[1:20] != '"Packet_Number": 1,':
                        status_label.configure(text='Error: Invalid QR code has been scanned.', font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
                        status_label.place(x=20, y=13)
                        time.sleep(1.5)

                    elif scanned_qr_data[0].data.decode('ascii') not in shamir_scan_values:
                        array = []
                        convert_shamir = json.loads(scanned_qr_data[0].data.decode('ascii'))
                        

                        if not convert_shamir['Threshold']:
                            raise KeyError
                        
                        scanned_shamir_listbox.insert(0, convert_shamir['QR-Name'])
                        if scanned_shamir_listbox.size() <= 1:
                            pass
                        else:
                            for i in range(0, scanned_shamir_listbox.size()):
                                op = scanned_shamir_listbox.get(i)
                                array.append(op)
                            sorted_array = natsorted(array)
                            scanned_shamir_listbox.delete(0, tk.END)

                            for y in range(0, len(sorted_array)):
                                scanned_shamir_listbox.insert(y, sorted_array[y])

                        shamir_scan_values.append(scanned_qr_data[0].data.decode('ascii'))
                        status_label.configure(text=f"{convert_shamir['QR-Name']} has been scanned successfully.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="green")
                        status_label.place(x=20, y=13)
                        continue_button.place(x=48, y=440)
                        time.sleep(1.5)

                    elif scanned_qr_data[0].data.decode('ascii') in shamir_scan_values:
                        convert_shamir = json.loads(scanned_qr_data[0].data.decode('ascii'))
                        status_label.configure(text=f"Error: {convert_shamir['QR-Name']} has been already scanned.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
                        status_label.place(x=20, y=13)
                        time.sleep(1.5)
                
                except KeyError:
                    status_label.configure(text=f"Error: Passphrase share does not include in this QR Code.", font=customtkinter.CTkFont(size=15, weight="bold"), text_color="red")
                    status_label.place(x=20, y=13)
                    time.sleep(1.5)

                except IndexError:
                    pass

                except tk.TclError:    
                    pass
                
                except TypeError:
                    break

def gen_gpg_pass(self, name, email, passphrase, input_entry4, gen_gpg_pass_win):
    global re_passp_error_count
    if passphrase == input_entry4.get():
        try:
            command1 = ["pass"]
            out1 = subprocess.check_output(command1, universal_newlines=False, stderr=subprocess.DEVNULL, shell=False)
        
        except FileNotFoundError:
            gen_gpg_pass_win.destroy()
            messagebox.showinfo('Error', 'A problem occured while generating a new pass store. Please make sure you have installed "pass".', parent=self)
            re_passp_error_count = 3
            main_window.App.enable_button(self)
        
        except subprocess.CalledProcessError:
        
            gpg = gnupg.GPG()

            if os.path.exists(password_store):
                shutil.rmtree(password_store)
            else:
                pass

            #GPG Key Generation
            key_info = gpg.gen_key_input( 
                name_real=name, 
                name_email=email,
                passphrase=passphrase, 
                key_type='eddsa', 
                key_curve='ed25519', 
                key_usage='sign', 
                subkey_type='ecdh', 
                subkey_curve='cv25519')
            
            key = gpg.gen_key(key_info)

            command2 = ["pass", "init", f"{key}"]
            out2 = subprocess.check_output(command2, universal_newlines=False, shell=False)

            passphrase = ""
            messagebox.showinfo('Success', 'New GPG key generated and a new pass store initialized.', parent=self)
            gen_gpg_pass_win.destroy()
            main_window.App.refresh(self)
            main_window.App.enable_button(self)
        
        else:

            gpg = gnupg.GPG()
            
            if os.path.exists(password_store):
                shutil.rmtree(password_store)
            else:
                pass

            key_info = gpg.gen_key_input(name_real=name, name_email=email, passphrase=passphrase, key_type='eddsa', 
                key_curve='ed25519', key_usage='sign', subkey_type='ecdh', subkey_curve='cv25519')

            key = gpg.gen_key(key_info)
            
            command2 = ["pass", "init", f"{key}"]
            out2 = subprocess.check_output(command2, universal_newlines=False, shell=False)
            
            passphrase = ""
            gen_gpg_pass_win.destroy()
            messagebox.showinfo('Success', 'New GPG key generated and a new pass store initialized.', parent=self)
            main_window.App.refresh(self)
            main_window.App.enable_button(self)

    else:
        re_passp_error_count -= 1
        if re_passp_error_count <= 0:
            messagebox.showinfo('', 'Symmetric encryption could not be completed due to incorrent passphrase input.', parent=gen_gpg_pass_win)
            passphrase = ""
            gen_gpg_pass_win.destroy()
            main_window.App.enable_button(self)
        else:
            messagebox.showinfo('Bad Passphrase', f'Passphrases do not match (try {re_passp_error_count} out of 3)', parent=gen_gpg_pass_win)

def get_passphrase(self, input_label, input_label2, input_entry3, email, enter_button, gen_gpg_pass_win, name, label5, label6, cancel_button):
    global passphrase
    
    special_characters = "!@#$%^&*()-+?_=,<>/"
    alphabet = "abcdefghijklmnopqrstuvwxyz"  
    numbers = "0123456789"
    passphrase = input_entry3.get()

    if passphrase == "":
        messagebox.showinfo('Invalid Passphrase', 'Passphrase should not be empty.', parent=gen_gpg_pass_win)

    else:
        if any(c in special_characters or c in numbers for c in passphrase) and any(c in alphabet.upper() or c in alphabet for c in passphrase) and len(passphrase) >=8:
            gen_gpg_pass_win.geometry("420x150")
            input_label.configure(text="Please re-enter your new passphrase")
            input_label2.place(x=50,y=63)
            label5.destroy()
            label6.destroy()
            input_entry3.destroy()
            input_entry4 = customtkinter.CTkEntry(gen_gpg_pass_win, show="*")
            input_entry4.place(x=130,y=63)
            enter_button.configure(command=lambda: gen_gpg_pass(self, name, email, passphrase, input_entry4, gen_gpg_pass_win))
            enter_button.place(x=50,y=100)
            cancel_button.place(x=125,y=100)

        else:
            if messagebox.askyesno('Weak Passphrase', 'Your passphrase is not considered strong. Do you wish to use this one?', parent=gen_gpg_pass_win):
                gen_gpg_pass_win.geometry("420x150")
                input_label.configure(text="Please re-enter your new passphrase")
                input_label2.place(x=50,y=63)
                label5.destroy()
                label6.destroy()
                input_entry3.destroy()
                input_entry4 = customtkinter.CTkEntry(gen_gpg_pass_win, show="*")
                input_entry4.place(x=130,y=63)
                enter_button.configure(command=lambda: gen_gpg_pass(self, name, email, passphrase, input_entry4, gen_gpg_pass_win))
                enter_button.place(x=50,y=100)
                cancel_button.place(x=125,y=100)

def get_email(self, input_label, input_label2, input_entry2, enter_button, gen_gpg_pass_win, name, cancel_button, instructions_label):
    email = input_entry2.get()
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]{1,}\b"
    if re.fullmatch(regex, email):
        gen_gpg_pass_win.geometry("500x200")
        input_entry2.destroy()
        input_label.configure(text="Please create a passphrase.")

        label5 = customtkinter.CTkLabel(gen_gpg_pass_win, text ="To create a secure passphrase, it should be at least 8 characters")
        label5.place(x=50,y=63)

        label6 = customtkinter.CTkLabel(gen_gpg_pass_win, text ="long and contain at least 1 digit or special character.")
        label6.place(x=50,y=83)

        instructions_label.configure(text="GPG Key Generation - Passphrase")
        input_label2.configure(text="Passphrase:")
        input_label2.place(x=50,y=118)
        input_entry3 = customtkinter.CTkEntry(gen_gpg_pass_win, show="*")
        input_entry3.place(x=130,y=118)
        enter_button.configure(command=lambda: get_passphrase(self, input_label, input_label2, input_entry3, email, enter_button, gen_gpg_pass_win, name, label5, label6, cancel_button))
        enter_button.place(x=50,y=158)
        cancel_button.place(x=125,y=158)

    elif email.isascii() == False:
        messagebox.showinfo('Invalid Email', 'Email should not contain non-ascii characters.', parent=gen_gpg_pass_win)
    else:
        messagebox.showinfo('Invalid Email','The email address you put is not valid.', parent=gen_gpg_pass_win)

def get_name(self, input_label, input_label2, input_entry, enter_button, gen_gpg_pass_win, cancel_button, instructions_label):
    name = input_entry.get()
    if name == "":
        messagebox.showinfo('Invalid Name', 'Name should not be empty.', parent=gen_gpg_pass_win)
    elif name.isascii() == False:
        messagebox.showinfo('Invalid Name', 'Name should not contain non-ascii characters.', parent=gen_gpg_pass_win)
    else:
        instructions_label.configure(text="GPG Key Generation - E-Mail")
        input_entry.destroy()
        input_label.configure(text="Please put your email address.")
        input_label2.configure(text="E-Mail:")
        input_entry2 = customtkinter.CTkEntry(gen_gpg_pass_win)
        input_entry2.place(x=100,y=63)
        enter_button.configure(command=lambda: get_email(self, input_label, input_label2, input_entry2, enter_button, gen_gpg_pass_win, name, cancel_button, instructions_label))

def gen_gpg_pass_win(self):
    gen_gpg_pass_win = customtkinter.CTkToplevel(self)
    gen_gpg_pass_win.title("Generate GPG Key & Pass Storage")
    gen_gpg_pass_win.geometry("420x150")
    gen_gpg_pass_win.resizable(False,False)
    gen_gpg_pass_win.protocol("WM_DELETE_WINDOW", lambda: exit_gen_gpg_passp(self, gen_gpg_pass_win))

    instructions_label = customtkinter.CTkLabel(gen_gpg_pass_win, text ="GPG Key Generation - Name", font=customtkinter.CTkFont(size=20, weight="bold"))
    instructions_label.place(x=50,y=10)

    input_label = customtkinter.CTkLabel(gen_gpg_pass_win, text ="Please put your real name.")
    input_label.place(x=50,y=35)

    input_label2 = customtkinter.CTkLabel(gen_gpg_pass_win, text ="Real Name:")
    input_label2.place(x=50,y=63)

    input_entry = customtkinter.CTkEntry(gen_gpg_pass_win)
    input_entry.place(x=125,y=63)

    enter_button = customtkinter.CTkButton(gen_gpg_pass_win, text="Enter", command=lambda: get_name(self, input_label, input_label2, input_entry, enter_button, gen_gpg_pass_win, cancel_button, instructions_label), width=60, fg_color="darkred", hover_color="#D2042D")
    enter_button.place(x=50,y=100)

    cancel_button = customtkinter.CTkButton(gen_gpg_pass_win, text="Cancel Generation", command=lambda: exit_gen_gpg_passp(self, gen_gpg_pass_win), fg_color="darkred", hover_color="#D2042D")
    cancel_button.place(x=125,y=100)

def gen_gpg_pass_start(self):
    #Check if pass exists in the machine.
    try:
        command1 = ["pass"]
        out1 = subprocess.check_output(command1, universal_newlines=False, stderr=subprocess.DEVNULL, shell=False)
        
    except FileNotFoundError:
        messagebox.showinfo('Error', 'A problem occured while generating a new pass store. Please make sure you have installed "pass".', parent=self)
        main_window.App.enable_button(self)
    
    except subprocess.CalledProcessError:
        main_window.App.disable_button(self)
        gen_gpg_pass_win(self)
    
    else:
        if os.path.exists(password_store):
            if messagebox.askyesno('Pass Storage Exists', 'There is an exiting pass storage located on your machine. Do you still wish to create a new one?', parent=self):
                main_window.App.disable_button(self)
                gen_gpg_pass_win(self)

#References
#Lines between 219-223 and 385-389 are inspired by: https://stackoverflow.com/questions/66956444/live-video-feed-from-camera-to-tkinter-window-with-opencv
#Lines 118, 199, 202, 204, 366, 369, 371, 541, 555, 578, 600, 621, 624 are implemented with the help of https://stackoverflow.com/questions/75480143/python-tkinter-removing-nested-functions. OGLOK is my username.