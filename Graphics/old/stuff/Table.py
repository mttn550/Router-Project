import tkinter as tk, tkinter.ttk as ttk


class Table(tk.Frame):

    def __init__(self, root, size, columns):
        super().__init__(root)
        self.columns = columns
        self.size = size
        self.table = self.draw_table(columns)

    def update_table(self, *args):
        if len(args) == len(self.columns):
            self.table.insert(parent='', index='end', text='', values=args)

    def __delitem__(self, key):
        for row in self.table.get_children():
            if self.table.item(row)['values'][0] == key:
                self.table.delete(row)
                break

    def draw_table(self, columns):
        scroll_x = tk.Scrollbar(self, orient='horizontal')
        scroll_y = tk.Scrollbar(self, orient='vertical')
        scroll_y.pack(side='right', fill='y')
        scroll_x.pack(side='bottom', fill='x')
        table = ttk.Treeview(self, columns=columns, height=self.size[1], show='headings', selectmode='browse',
                             xscrollcommand=scroll_x.set, yscrollcommand=scroll_y.set)
        style = ttk.Style()
        style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
        table.insert('', tk.END, iid=1, values=('Time1', 'Source1', 'Destination1', 'Protocol1', 'Data1'))
        table.column('#0', width=0, stretch=tk.NO)
        for i in range(len(columns)):
            if i == len(columns) - 1:
                table.column(columns[i], width=self.size[0] - (self.size[0] // len(columns) - self.size[0] // 25) * len(columns),
                             minwidth=self.size[0] - (self.size[0] // len(columns) - self.size[0] // 25) * len(columns),
                             stretch=False, anchor='center')
            else:
                table.column(columns[i], width=self.size[0] // len(columns) - self.size[0] // 25,
                             minwidth=self.size[0] // len(columns) - self.size[0] // 25,
                             stretch=False, anchor='center')
            table.heading(columns[i], text=columns[i], anchor='center')
        table.pack(fill='x')
        scroll_y.config(command=table.yview)
        scroll_x.config(command=table.xview)
        return table