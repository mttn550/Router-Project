import tkinter as tk
from tkinter import ttk

class GUI:

    def __init__(self, table_data):
        self.root = tk.Tk()
        self.basic_data()
        self.table_data = table_data

    def basic_data(self):
        tk.Label(self.root, font=('Arial', '18', 'bold'), text='Router up and running!').pack(side='top', pady=10)
        self.pkts = GUI.table(self.root, ['Source', 'Destination'])
        self.pkts[1].pack(side='left', padx=25, pady=40)
        self.clients = GUI.table(self.root, ['MAC', 'IP'])
        self.clients[1].pack(side='left', padx=25, pady=40)

    def update_tables(self):
        while True:
            while self.table_data[0]:
                self.pkts[0].insert(parent='', index='end', text='', values=self.table_data[0].pop(0))
                self.pkts[0].yview_moveto(1)
            while self.table_data[1]:
                self.pkts[0].insert(parent='', index='end', text='', values=self.table_data[1].pop(0))
                self.pkts[0].yview_moveto(1)

    def start(self):
        self.root.mainloop()

    @staticmethod
    def table(root, columns):
        frame = tk.Frame(root)

        scroll_x = tk.Scrollbar(frame, orient='horizontal')
        scroll_y = tk.Scrollbar(frame, orient='vertical')
        scroll_y.pack(side='right', fill='y')
        scroll_x.pack(side='bottom', fill='x')

        table = ttk.Treeview(frame, columns=columns, xscrollcommand=scroll_x.set,
                             yscrollcommand=scroll_y.set)
        table.column('#0', width=0, stretch=False)
        table.heading('#0', text='', anchor='center')

        for i in range(len(columns)):
            table.column(columns[i], anchor='center')
            table.heading(columns[i], text=columns[i], anchor='center')

        table.pack()
        scroll_y.config(command=table.yview)
        scroll_x.config(command=table.xview)

        return table, frame
