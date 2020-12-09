from Tiny_File_Encrypter import *
from tkinter import *
from tkinter import filedialog

root = Tk()  # Blank window
root.title('AES Simulator')
root.geometry("550x450")
text = Label(root, text='Please input password to access encryption program: ')
text.pack()

e = Entry(root, width=25, borderwidth=4)  # Size of the input box
e.pack()
input = e.get()

topFrame = Frame(root)
topFrame.pack()
bottomFrame = Frame(root)
bottomFrame.pack(side=BOTTOM)


def openFile():  # this is whats going to happen when the submit button gets clicked
   root.filename = filedialog.askopenfilename(initialdir="/Users/ericcuevas", title="Select a file")  # selects a file
   myLabel1 = Label(root, text=root.filename).pack()


button1 = Button(topFrame, text="Submit")

myButton = Button(root, text="Submit", command=passCheck(input))
myButton.pack()

root.mainloop()
