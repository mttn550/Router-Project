from Graphics.old.stuff.Table import Table
import tkinter as tk


root = tk.Tk()
root.geometry('780x250')

tk.Label(root, text='Router up and running!', font='Assistant 18 bold').pack(side='top')
Table(root, (650, 150), ('Time', 'Source', 'Destination', 'Protocol', 'Data')).pack(side='top', padx=10, pady=10)

if __name__ == '__main__':
    root.mainloop()