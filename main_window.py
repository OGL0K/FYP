import os
import subprocess
import customtkinter
import tkinter as tk

import export_qr
import import_qr
from tkinter import messagebox

pwd = os.path.expanduser('~')
customtkinter.set_appearance_mode("System")

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title('PassQR')
        self.geometry("600x400")
        self.resizable(False,False)

        # create sidebar frame with widgets
        self.sidebar_frame = customtkinter.CTkFrame(self, width=170, height=700, corner_radius=0)
        self.sidebar_frame.place(x=0, y=0)

        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="PassQR", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.place(x=45, y=30)

        #Home Tab
        self.sidebar_button_1 = customtkinter.CTkButton(self.sidebar_frame, text="Home", command=self.home_window, fg_color="darkred", hover_color="#D2042D")
        self.sidebar_button_1.place(x=15, y=80)

        #Convert Tab
        self.sidebar_button_2 = customtkinter.CTkButton(self.sidebar_frame, text="Backup Passwords", command=self.convert_window, fg_color="darkred", hover_color="#D2042D")
        self.sidebar_button_2.place(x=15, y=130)

        #Import Tab
        self.sidebar_button_3 = customtkinter.CTkButton(self.sidebar_frame, text="Recover Passwords", command=self.import_window,  fg_color="darkred", hover_color="#D2042D")
        self.sidebar_button_3.place(x=15, y=180)

        #Exit Button
        self.exit_button = customtkinter.CTkButton(self.sidebar_frame, text="Exit", command=self.quit_app,  fg_color="darkred", hover_color="#D2042D")
        self.exit_button.place(x=15, y=330)

        #Default Home Label
        self.label1 = customtkinter.CTkLabel(self, text="Welcome to PassQR", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.label1.place(x=300, y=30)

        #Pass Files Listbox
        self.passfiles_lb = tk.Listbox(self, selectmode=tk.MULTIPLE, height=9)
        self.subdir_file_arr = []
        for path, subdirs, files in os.walk(f"{pwd}/.password-store"):
            for name in files:
                if name.endswith('.gpg'):
                    self.joined = os.path.join(path, name)
                    self.joined_2 = self.joined.replace(f"{pwd}/.password-store/", "")
                    self.final_joined2 = self.joined_2.replace(".gpg", "")
                    self.subdir_file_arr.append(self.final_joined2)

        else:  
            pass

        for x in range(0, len(self.subdir_file_arr)):
            self.passfiles_lb.insert(x, self.subdir_file_arr[x])
        
        #Convert Button
        self.convert = customtkinter.CTkButton(self, text="Convert Selected Files", command=self.convertFiles, fg_color="darkred", hover_color="#D2042D", width=185)

        #Convert All Button
        self.convertall = customtkinter.CTkButton(self, text="Convert All Files", command=self.convertAllFiles, fg_color="darkred", hover_color="#D2042D", width=185)

        #Refresh Button
        self.refresh_files = customtkinter.CTkButton(self, text="Refresh Pass Store", command=self.refresh, fg_color="darkred", hover_color="#D2042D", width=185)

        #Scan QR Button
        self.scan_button = customtkinter.CTkButton(self, text='Scan QR Code', command=lambda: import_qr.scan_qr_start(self), fg_color="darkred", hover_color="#D2042D",  width=225)

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
            messagebox.showinfo('Not Selected', 'Please choose a file')
        else:
            self.pass_files = []
            
            if messagebox.askyesno('Convert', f'Are you sure to convert the selected file(s)?'):
                
                kill_command = ["gpgconf", "--kill", "gpg-agent"]
                kill_out = subprocess.check_output(kill_command, universal_newlines=False)
                self.disable_button()

                for val in self.files:
                    self.pass_files.append(f'{pwd}/.password-store/{val}')
                
                export_qr.asym_dec_window(self, self.pass_files , self.files)

    def convertAllFiles(self):
        if os.path.exists(f"{pwd}/.password-store"):
            self.files = []
            for i in range(0, self.passfiles_lb.size()):
                self.op = self.passfiles_lb.get(i)
                self.files.append(self.op)

            if self.files == []:
                messagebox.showinfo('Empty Store', 'Your pass store is empty.')

            else:
                self.pass_files = []
                
                if messagebox.askyesno('Convert', f'Are you sure to convert all files?'):
                    
                    kill_command = ["gpgconf", "--kill", "gpg-agent"]
                    kill_out = subprocess.check_output(kill_command, universal_newlines=False)
                    self.disable_button()

                    for val in self.files:
                        self.pass_files.append(f'{pwd}/.password-store/{val}')
                    
                    export_qr.asym_dec_window(self, self.pass_files , self.files)
        else:
            messagebox.showinfo('No pass store', 'Pass store could not be found on your machine.')

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
            
            messagebox.showinfo('Refreshed', 'Your pass store has been refreshed.')
        else:
            messagebox.showinfo('No pass store', 'Pass store could not be found on your machine.')

    def home_window(self):
        self.label1.configure(text="Welcome to PassQR")
        self.label1.place(x=300, y=30)

        self.passfiles_lb.place_forget()
        self.convert.place_forget()
        self.convertall.place_forget()
        self.refresh_files.place_forget()
        self.scan_button.place_forget()
        self.shamir_button.place_forget()
        self.gen_gpg_pass_button.place_forget()

    def convert_window(self):
        self.label1.configure(text="PassQR-Convert")
        self.label1.place(x=300, y=30)

        self.scan_button.place_forget()
        self.shamir_button.place_forget()
        self.gen_gpg_pass_button.place_forget()

        self.passfiles_lb.place(x=300, y=70)
        self.convert.place(x=300, y=250)
        self.convertall.place(x=300, y=290)
        self.refresh_files.place(x=300, y=330)

    def import_window(self):
        self.label1.configure(text="PassQR-Import")
        self.label1.place(x=310, y=30)
        self.scan_button.place(x=270, y=140)
        self.shamir_button.place(x=270, y=180)
        self.gen_gpg_pass_button.place(x=270, y=220)

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

    def cancel_convert(self, newWindow):
        newWindow.destroy()
        self.enable_button()

    def disable_close(self):
        pass

    def quit_app(self):
        quit_question = messagebox.askquestion('Exit App', 'Are you sure exitting the applicaiton?').upper()
        if quit_question[0] == 'Y':
            self.quit()
        else:
            return None

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", App.quit_app)
    app.mainloop()