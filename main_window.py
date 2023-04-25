import os
import subprocess
import customtkinter
import tkinter as tk

import export_qr
import import_qr
from tkinter import messagebox

gpg_id_count = 0
pwd = os.path.expanduser('~')
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

        self.sidebar_frame = customtkinter.CTkFrame(self, width=170, height=700, corner_radius=0)
        self.sidebar_frame.place(x=0, y=0)

        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="PassQR", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.place(x=45, y=30)

        #Home Tab
        self.sidebar_button_1 = customtkinter.CTkButton(self.sidebar_frame, text="Home", command=self.home_page, fg_color="darkred", hover_color="#D2042D")
        self.sidebar_button_1.place(x=15, y=80)

        #Convert Tab
        self.sidebar_button_2 = customtkinter.CTkButton(self.sidebar_frame, text="Backup", command=self.backup_page, fg_color="darkred", hover_color="#D2042D")
        self.sidebar_button_2.place(x=15, y=130)

        #Import Tab
        self.sidebar_button_3 = customtkinter.CTkButton(self.sidebar_frame, text="Recover", command=self.recover_page,  fg_color="darkred", hover_color="#D2042D")
        self.sidebar_button_3.place(x=15, y=180)

        #Exit Button
        self.exit_button = customtkinter.CTkButton(self.sidebar_frame, text="Exit", command=self.quit_app,  fg_color="darkred", hover_color="#D2042D")
        self.exit_button.place(x=15, y=350)

        #Default Home Label
        self.label1 = customtkinter.CTkLabel(self, text="Home", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.label1.place(x=337, y=30)

        self.label2 = customtkinter.CTkLabel(self, text="Password List", font=customtkinter.CTkFont(size=13, weight="bold"))

        self.home_label1 = customtkinter.CTkLabel(self, text="PassQR has been developed to backup and recover\npasswords securely and easlily that is located on pass.")
        self.home_label1.place(x=210, y=60)

        self.home_label2 = customtkinter.CTkLabel(self, text="Backup", font=customtkinter.CTkFont(size=13, weight="bold"))
        self.home_label2.place(x=340, y=95)

        self.home_label3 = customtkinter.CTkLabel(self, text="Backing up your passwords is really simple. You can\n backup your passwords however you like. It can be\n backed up all together or you can backup passwords\n by choosing from the list. If you made any changes in\n your pass repository, you can hit refresh button to\n refresh your pass list.")
        self.home_label3.place(x=210, y=120)

        self.home_label4 = customtkinter.CTkLabel(self, text="Recover", font=customtkinter.CTkFont(size=13, weight="bold"))
        self.home_label4.place(x=340, y=220)

        self.home_label5 = customtkinter.CTkLabel(self, text="To recover your passwords, firstly scan your QR\n codes. After a successful scan, you have to provide\n your passphrase that you have generated in backup\n process. Once that is done, you are good to go! If\n you forget your passphrase and you have more than\n one copy, do not worry. You can use retreive your\n passphrase by scanning your first QR code of your copies.\n Also, you can generate a new GPG key and pass storage.")
        self.home_label5.place(x=190, y=245)

        #Password Listbox
        self.passfiles_lb = tk.Listbox(self, selectmode=tk.MULTIPLE, height=9)
        self.subdir_file_arr = []
        for path, subdirs, files in os.walk(f"{pwd}/.password-store"):
            for name in files:
                if name.endswith('.gpg'):
                    self.joined = os.path.join(path, name)
                    self.joined_2 = self.joined.replace(f"{pwd}/.password-store/", "")
                    self.final_joined2 = self.joined_2.replace(".gpg", "")
                    self.subdir_file_arr.append(self.final_joined2)

        for x in range(0, len(self.subdir_file_arr)):
            self.passfiles_lb.insert(x, self.subdir_file_arr[x])
        
        #Convert Button
        self.convert = customtkinter.CTkButton(self, text="Backup Selected Passwords", command=self.convertFiles, fg_color="darkred", hover_color="#D2042D", width=185)

        #Convert All Button
        self.convertall = customtkinter.CTkButton(self, text="Backup All Passwords", command=self.convertAllFiles, fg_color="darkred", hover_color="#D2042D", width=185)

        #Refresh Button
        self.refresh_files = customtkinter.CTkButton(self, text="Refresh List", command=self.refresh, fg_color="darkred", hover_color="#D2042D", width=185)

        #Scan QR Button
        self.scan_button = customtkinter.CTkButton(self, text='Recover Passwords', command=lambda:import_qr.scan_qr_start(self), fg_color="darkred", hover_color="#D2042D",  width=225)

        #Retreive Passphrase with Shamir Button
        self.shamir_button = customtkinter.CTkButton(self, text='Retrieve Passphrase', command=lambda:import_qr.shamir_scan_start(self), fg_color="darkred", hover_color="#D2042D",  width=225)

        #Generate New GPG Key and Pass Storage Button
        self.gen_gpg_pass_button = customtkinter.CTkButton(self, text='Generate GPG Key & Pass Storage', command=lambda:import_qr.gen_gpg_pass_start(self), fg_color="darkred", hover_color="#D2042D",  width=185)

    def convertFiles(self):
        self.files = []

        self.cname = self.passfiles_lb.curselection()
        for i in self.cname:
            self.op = self.passfiles_lb.get(i)
            self.files.append(self.op)
        if self.files == []:
            messagebox.showinfo('File(s) Not Selected', 'Please choose a file', parent=self)
        else:
            self.pass_files = []
            
            if messagebox.askyesno('Convert', f'Are you sure to convert the selected file(s)?', parent=self):
                
                kill_command = ["gpgconf", "--kill", "gpg-agent"]
                kill_out = subprocess.check_output(kill_command, universal_newlines=False, shell=False)
                self.disable_button()

                for val in self.files:
                    self.pass_files.append(f'{pwd}/.password-store/{val}')
                
                export_qr.asym_dec_window(self, self.pass_files , self.files)

    def convertAllFiles(self):
        if os.path.exists(f"{pwd}/.password-store"):
            global gpg_id_count
            check_files = []
            for path, subdirs, files2 in os.walk(f"{pwd}/.password-store"):
                for name in files2:
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
                    
                    if messagebox.askyesno('Convert', f'Are you sure to convert all files?', parent=self):
                        
                        kill_command = ["gpgconf", "--kill", "gpg-agent"]
                        kill_out = subprocess.check_output(kill_command, universal_newlines=False)
                        self.disable_button()

                        for val in self.files:
                            self.pass_files.append(f'{pwd}/.password-store/{val}')
                        
                        export_qr.asym_dec_window(self, self.pass_files , self.files)
                        gpg_id_count = 0
        else:
            messagebox.showinfo('No pass store', 'Pass store could not be found on your machine.', parent=self)

    def refresh(self):
        if os.path.exists(f"{pwd}/.password-store"):
            self.subdir_file_arr = []
            for path, subdirs, files in os.walk(f"{pwd}/.password-store"):
                for name in files:
                    if name.endswith('.gpg'):
                        self.joined = os.path.join(path, name)
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

        self.home_label1.place(x=210, y=60)
        self.home_label2.place(x=340, y=95)
        self.home_label3.place(x=210, y=120)
        self.home_label4.place(x=340, y=220)
        self.home_label5.place(x=190, y=245)

        self.label2.place_forget()
        self.passfiles_lb.place_forget()
        self.convert.place_forget()
        self.convertall.place_forget()
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
        self.home_label4.place_forget()
        self.home_label5.place_forget()
        self.scan_button.place_forget()
        self.shamir_button.place_forget()
        self.gen_gpg_pass_button.place_forget()

        self.label2.place(x=330, y=55)
        self.passfiles_lb.place(x=285, y=85)
        self.convert.place(x=285, y=250)
        self.convertall.place(x=285, y=290)
        self.refresh_files.place(x=285, y=330)

    def recover_page(self):
        self.label1.configure(text="Recover")

        self.scan_button.place(x=270, y=140)
        self.shamir_button.place(x=270, y=180)
        self.gen_gpg_pass_button.place(x=270, y=220)

        self.home_label1.place_forget()
        self.home_label2.place_forget()
        self.home_label3.place_forget()
        self.home_label4.place_forget()
        self.home_label5.place_forget()
        self.label2.place_forget()
        self.passfiles_lb.place_forget()
        self.convert.place_forget()
        self.convertall.place_forget()
        self.refresh_files.place_forget()

    def disable_button(self):
        self.sidebar_button_1.configure(state= customtkinter.DISABLED)
        self.sidebar_button_2.configure(state= customtkinter.DISABLED)
        self.sidebar_button_3.configure(state= customtkinter.DISABLED)
        self.convert.configure(state= customtkinter.DISABLED)
        self.convertall.configure(state= customtkinter.DISABLED)
        self.refresh_files.configure(state= customtkinter.DISABLED)
        self.scan_button.configure(state= customtkinter.DISABLED)
        self.shamir_button.configure(state= customtkinter.DISABLED)
        self.gen_gpg_pass_button.configure(state= customtkinter.DISABLED)

    def enable_button(self):
        self.sidebar_button_1.configure(state= customtkinter.NORMAL)
        self.sidebar_button_2.configure(state= customtkinter.NORMAL)
        self.sidebar_button_3.configure(state= customtkinter.NORMAL)
        self.convert.configure(state= customtkinter.NORMAL)
        self.convertall.configure(state= customtkinter.NORMAL)
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
#Lines 100, 103, and 106 are implemented with the help of https://stackoverflow.com/questions/75480143/python-tkinter-removing-nested-functions. OGLOK is my username.