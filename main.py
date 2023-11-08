import tkinter.messagebox
from tkinter import *
import fernet



# encrypted notes and passwords dictioanary
note_password = dict()


#UI

window = Tk()
window.title("Secret Notes")
window.minsize(width=450,height=800)

# Note Title

user_title = Label(text="Enter Your Title")
user_title.config(font=("Ariel",20,"normal"),
                  padx=15,pady=15)
user_title.pack()

# Title Entry

usertitle_entr = Entry(
    width=40,
)
usertitle_entr.focus()
usertitle_entr.pack()

# Secret text Label
usernot_label = Label(text="Enter Your Secret",
                      font=("Ariel",20,"normal"),
                      pady=15,padx=15)
usernot_label.pack()

# Secret Text

user_not = Text(
    width=50,
    height=20
)
user_not.pack()

# fernet
key = fernet.Fernet.generate_key()
fernet_ = fernet.Fernet(key)

# func
def encrypt():
    file = open("Notes.txt", "a")
    global fernet_
    global note_password
    global usertitle_entr
    password = str(master_key_entry.get())
    text_To_encrypt = user_not.get("1.0","end")
    if password == "" or text_To_encrypt == ""or text_To_encrypt == "\n" or usertitle_entr == "":
        message_warning = tkinter.messagebox.showwarning(title="Error!",
                                                         message="You have to fill all informations!!")
    else:
        encrypted_text = str(fernet_.encrypt(text_To_encrypt))
        encrypted_text_to_save = (encrypted_text[2:-1]+"\n")
        entry_str = str(usertitle_entr.get())
        file.write("\n")
        file.write(" Title : {}".format(entry_str))
        file.write("\n")
        file.write(str(encrypted_text_to_save))
        note_password[str(encrypted_text_to_save)] = password
        usertitle_entr.delete(0,"end")
        user_not.delete("1.0","end")
        master_key_entry.delete(0,"end")

        file.close()

def decrypt():
    global fernet_
    global note_password
    password2 = str(master_key_entry.get())
    text_to_decrypt = user_not.get("1.0","end")
    text_to_decrypt_str = str(text_to_decrypt)
    text_to_decrypt_byte = bytes(text_to_decrypt , "utf-8")
    try:
        if note_password[text_to_decrypt_str] == password2:
            decrypted_text = str(fernet_.decrypt(text_to_decrypt_byte).decode())
            user_not.delete("1.0","end")
            user_not.insert("1.0",str(decrypted_text))

        elif password2 == "\n" or password2 == "":
            message_warning = tkinter.messagebox.showwarning(title="Error!",
                                                            message="You have to fill the password!!")

        else:
            message_warning1 = tkinter.messagebox.showwarning(title="Error!",
                                                             message="Wrong Password!!")


    except:
        if text_to_decrypt_str not in note_password.values():
            message_warning2 = tkinter.messagebox.showwarning(title="Error!",
                                                            message="This text is not encrypted by this app!! ")
        else:
            message_warning3 = tkinter.messagebox.showwarning(title="Error!",
                                                              message="Unexpected Error!! ")



# master key Label
master_key_label = Label(text="Enter Master Key",
                         font=("Ariel",20,"normal"),
                         padx=15,pady=15)
master_key_label.pack()

# master key Entry
master_key_entry = Entry(width=40)
master_key_entry.pack()


# Save & encrypt Button
save_encrytp_button = Button(text="Save & Encrypt",
                             font=("Ariel",8,"normal"),
                             width=15,
                             command=encrypt)
save_encrytp_button.pack()

# decrypt Button
decrytp_button = Button(text="Decrypt",
                        font=("Ariel",8,"normal"),
                        width=12,
                        command=decrypt)
decrytp_button.pack()

window.mainloop()