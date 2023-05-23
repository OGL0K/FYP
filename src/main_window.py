import os
import subprocess
import customtkinter
import tkinter as tk

import backup
import recover
from tkinter import messagebox

#Global Variable
gpg_id_count = 0

#Path
pwd = os.path.expanduser('~')

#Application Apperance is based on the System's Appearance
customtkinter.set_appearance_mode("System")

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title('PassQR')
        width = 585
        height = 400
        
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        
        x = (screen_width/2) - (width/2)
        y = (screen_height/2) - (height/2)

        #Centering the application
        self.geometry('%dx%d+%d+%d' % (width, height, x, y))
        self.resizable(False,False)
        self.protocol("WM_DELETE_WINDOW", self.quit_app)

        self.sidebar = customtkinter.CTkFrame(self, width=170, height=700, corner_radius=0)
        self.sidebar.place(x=0, y=0)

        self.logo_label = customtkinter.CTkLabel(self.sidebar, text="PassQR", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.place(x=45, y=30)

        #Home Tab
        self.side_button1 = customtkinter.CTkButton(self.sidebar, text="Home", command=self.home_page, fg_color="darkred", hover_color="#D2042D")
        self.side_button1.place(x=15, y=80)

        #Backup Tab
        self.side_button2 = customtkinter.CTkButton(self.sidebar, text="Backup", command=self.backup_page, fg_color="darkred", hover_color="#D2042D")
        self.side_button2.place(x=15, y=130)

        #Recovery Tab
        self.side_button3 = customtkinter.CTkButton(self.sidebar, text="Recover", command=self.recover_page,  fg_color="darkred", hover_color="#D2042D")
        self.side_button3.place(x=15, y=180)

        #Exit Button
        self.exit_button = customtkinter.CTkButton(self.sidebar, text="Exit", command=self.quit_app,  fg_color="darkred", hover_color="#D2042D")
        self.exit_button.place(x=15, y=350)

        #Default Home Label
        self.label1 = customtkinter.CTkLabel(self, text="Home", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.label1.place(x=337, y=30)

        self.label2 = customtkinter.CTkLabel(self, text="Password List", font=customtkinter.CTkFont(size=13, weight="bold"))

        self.home_label1 = customtkinter.CTkLabel(self, text="PassQR is an application to backup and recover\nyour passwords securely that is located on pass.")
        self.home_label1.place(x=220, y=60)

        self.home_label2 = customtkinter.CTkLabel(self, text="PassQR simply converts your passwords into QR\ncode backups. You can print your backups and\nstore them physically which is harder for hackers to\nsteal your passwords. It is very easy to backup\nyour passwords, just follow the instructions. You\ncan refresh your password list if you have made\nchanges in your pass storage.")
        self.home_label2.place(x=210, y=110)

        self.home_label3 = customtkinter.CTkLabel(self, text="Recovering your passwords is really simple, firstly\nscan your QR codes. After a successful scan, you\nneed to provide your passphrase that you have\ngenerated in backup process. Once that is done, you are\ngood to go! If you forget your passphrase and you have\nmore than one copy, do not worry. You can use retreive\nyour passphrase by scanning your first QR code of your copies.\nAlso, you can generate a new GPG key and pass storage.")
        self.home_label3.place(x=180, y=235)

        #Password Listbox
        self.passfiles_lb = tk.Listbox(self, selectmode=tk.MULTIPLE, height=9)
        self.subdir_file_arr = []
        for main_path, sub_directories, files in os.walk(f"{pwd}/.password-store"):
            for file_name in files:
                if file_name.endswith('.gpg'):
                    self.joined = os.path.join(main_path, file_name)
                    self.joined_2 = self.joined.replace(f"{pwd}/.password-store/", "")
                    self.final_joined2 = self.joined_2.replace(".gpg", "")
                    self.subdir_file_arr.append(self.final_joined2)

        for x in range(0, len(self.subdir_file_arr)):
            self.passfiles_lb.insert(x, self.subdir_file_arr[x])
        
        #Backup Button
        self.backup = customtkinter.CTkButton(self, text="Backup Selected Passwords", command=self.backupPasswords, fg_color="darkred", hover_color="#D2042D", width=185)

        #Backup All Button
        self.backupall = customtkinter.CTkButton(self, text="Backup All Passwords", command=self.backupAllPasswords, fg_color="darkred", hover_color="#D2042D", width=185)

        #Refresh Button
        self.refresh_files = customtkinter.CTkButton(self, text="Refresh List", command=self.refresh, fg_color="darkred", hover_color="#D2042D", width=185)

        #Scan QR Button
        self.scan_button = customtkinter.CTkButton(self, text='Recover Passwords', command=lambda:recover.scan_qr_start(self), fg_color="darkred", hover_color="#D2042D",  width=225)

        #Retreive Passphrase with Shamir Button
        self.shamir_button = customtkinter.CTkButton(self, text='Retrieve Passphrase', command=lambda:recover.shamir_scan_start(self), fg_color="darkred", hover_color="#D2042D",  width=225)

        #Generate New GPG Key and Pass Storage Button
        self.gen_gpg_pass_button = customtkinter.CTkButton(self, text='Generate GPG Key & Pass Storage', command=lambda:recover.gen_gpg_pass_start(self), fg_color="darkred", hover_color="#D2042D",  width=185)

    def backupPasswords(self):
        self.files = []

        self.cname = self.passfiles_lb.curselection()
        for i in self.cname:
            self.op = self.passfiles_lb.get(i)
            self.files.append(self.op)
        if self.files == []:
            messagebox.showinfo('File(s) Not Selected', 'Please choose a file', parent=self)
        else:
            self.pass_files = []
            
            if messagebox.askyesno('Backup', f'Are you sure to backup the selected password(s)?', parent=self):
                
                kill_command = ["gpgconf", "--kill", "gpg-agent"]
                kill_out = subprocess.check_output(kill_command, universal_newlines=False, shell=False)
                self.disable_button()

                for val in self.files:
                    self.pass_files.append(f'{pwd}/.password-store/{val}')
                
                backup.asym_dec_window(self, self.pass_files , self.files)

    def backupAllPasswords(self):
        if os.path.exists(f"{pwd}/.password-store"):
            global gpg_id_count
            for main_path, sub_directories, files in os.walk(f"{pwd}/.password-store"):
                for name in files:
                    if name.endswith('.gpg-id'):
                        gpg_id_count +=1
            
            if gpg_id_count >= 2:
                messagebox.showinfo('Multiple GPG IDs', 'One or more subfolders have different GPG IDs. Therefore, passwords cannot be backed up all together. You can still backup your subfolders that have different GPG IDs individually by selecting the files that are inside that subfolder. If you select other files that is encrypted with different GPG ID, you cannot backup your passwords.', parent=self)
                gpg_id_count = 0
            else:

                self.files = []
                for i in range(0, self.passfiles_lb.size()):
                    self.op = self.passfiles_lb.get(i)
                    self.files.append(self.op)

                if self.files == []:
                    messagebox.showinfo('Empty Store', 'Your pass store is empty.', parent=self)

                else:
                    self.pass_files = []
                    
                    if messagebox.askyesno('Backup', f'Are you sure to backup all passwords?', parent=self):
                        
                        kill_command = ["gpgconf", "--kill", "gpg-agent"]
                        kill_out = subprocess.check_output(kill_command, universal_newlines=False)
                        self.disable_button()

                        for val in self.files:
                            self.pass_files.append(f'{pwd}/.password-store/{val}')

                        backup.asym_dec_window(self, self.pass_files , self.files)
                        gpg_id_count = 0
                    else:
                        gpg_id_count = 0
        else:
            messagebox.showinfo('No pass store', 'Pass store could not be found on your machine.', parent=self)

    def refresh(self):
        if os.path.exists(f"{pwd}/.password-store"):
            self.subdir_file_arr = []
            for main_path, sub_directories, files in os.walk(f"{pwd}/.password-store"):
                for name in files:
                    if name.endswith('.gpg'):
                        self.joined = os.path.join(main_path, name)
                        self.joined_2 = self.joined.replace(f"{pwd}/.password-store/", "")
                        self.final_joined2 = self.joined_2.replace(".gpg", "")
                        self.subdir_file_arr.append(self.final_joined2)

            self.passfiles_lb.delete(0, tk.END)

            for y in range(0, len(self.subdir_file_arr)):
                self.passfiles_lb.insert(y, self.subdir_file_arr[y])
            
            messagebox.showinfo('Refreshed', 'Your password list has been refreshed.', parent=self)
        else:
            messagebox.showinfo('No pass store', 'Pass store could not be found on your machine.', parent=self)

    #Home Tab Function
    def home_page(self):
        self.label1.configure(text="Home")

        self.home_label1.place(x=220, y=60)
        self.home_label2.place(x=210, y=110)
        self.home_label3.place(x=180, y=235)

        self.label2.place_forget()
        self.passfiles_lb.place_forget()
        self.backup.place_forget()
        self.backupall.place_forget()
        self.refresh_files.place_forget()
        self.scan_button.place_forget()
        self.shamir_button.place_forget()
        self.gen_gpg_pass_button.place_forget()

    #Backup Tab Function
    def backup_page(self):
        self.label1.configure(text="Backup")
        
        self.home_label1.place_forget()
        self.home_label2.place_forget()
        self.home_label3.place_forget()
        self.scan_button.place_forget()
        self.shamir_button.place_forget()
        self.gen_gpg_pass_button.place_forget()

        self.label2.place(x=330, y=55)
        self.passfiles_lb.place(x=285, y=85)
        self.backup.place(x=285, y=250)
        self.backupall.place(x=285, y=290)
        self.refresh_files.place(x=285, y=330)

    def recover_page(self):
        self.label1.configure(text="Recover")

        self.scan_button.place(x=270, y=140)
        self.shamir_button.place(x=270, y=180)
        self.gen_gpg_pass_button.place(x=270, y=220)

        self.home_label1.place_forget()
        self.home_label2.place_forget()
        self.home_label3.place_forget()
        self.label2.place_forget()
        self.passfiles_lb.place_forget()
        self.backup.place_forget()
        self.backupall.place_forget()
        self.refresh_files.place_forget()

    def disable_button(self):
        self.side_button1.configure(state= customtkinter.DISABLED)
        self.side_button2.configure(state= customtkinter.DISABLED)
        self.side_button3.configure(state= customtkinter.DISABLED)
        self.backup.configure(state= customtkinter.DISABLED)
        self.backupall.configure(state= customtkinter.DISABLED)
        self.refresh_files.configure(state= customtkinter.DISABLED)
        self.scan_button.configure(state= customtkinter.DISABLED)
        self.shamir_button.configure(state= customtkinter.DISABLED)
        self.gen_gpg_pass_button.configure(state= customtkinter.DISABLED)

    def enable_button(self):
        self.side_button1.configure(state= customtkinter.NORMAL)
        self.side_button2.configure(state= customtkinter.NORMAL)
        self.side_button3.configure(state= customtkinter.NORMAL)
        self.backup.configure(state= customtkinter.NORMAL)
        self.backupall.configure(state= customtkinter.NORMAL)
        self.refresh_files.configure(state= customtkinter.NORMAL)
        self.scan_button.configure(state= customtkinter.NORMAL)
        self.shamir_button.configure(state= customtkinter.NORMAL)
        self.gen_gpg_pass_button.configure(state= customtkinter.NORMAL)

    def disable_close(self):
        pass

    def quit_app(self):
        quit_question = messagebox.askquestion('Exit App', 'Are you sure exitting the applicaiton?', parent=self).upper()
        if quit_question[0] == 'Y':
            self.quit()
        else:
            return None

if __name__ == "__main__":
    app = App()
    app.mainloop()

#References
#Lines 99, 102, and 105 are implemented with the help of https://stackoverflow.com/questions/75480143/python-tkinter-removing-nested-functions. Oguz Gokyuzu is my username.