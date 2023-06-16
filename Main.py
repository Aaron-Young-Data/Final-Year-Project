from doctest import master
import re
import threading
import tkinter as tk
import nmap
import networkx as nx
import matplotlib.pyplot as plt
import pyshark
import tkinter.font as tkFont
from tkinter import END, messagebox
import tkthread; tkthread.tkinstall()


class Main_Menu:
    def __init__(self, master):
        self.master = master

        self.label = tk.Label(text="Main Menu", font=20)
        self.label.grid(column=1, row=1, columnspan=2, sticky=tk.NSEW, padx=20, pady=30)

        self.down_btn = tk.Button(master, text="Down Detection", command=self.down_com, width=20, height=5)
        self.down_btn.grid(column=1, row=2, sticky=tk.NSEW, padx=20, pady=30)
        
        self.mapping_btn = tk.Button(master, text="Network Mapping", command=self.mapping_com, width=20, height=5)
        self.mapping_btn.grid(column=2, row=2, sticky=tk.NSEW, padx=20, pady=30)
        
        self.traffic_btn = tk.Button(master, text="Network Traffic", command=self.traffic_com, width=20, height=5)
        self.traffic_btn.grid(column=1, row=3, sticky=tk.NSEW, padx=20, pady=30)
    
        self.packets_btn = tk.Button(master, text="Network Packets", command=self.packets_com, width=20, height=5)
        self.packets_btn.grid(column=2, row=3, sticky=tk.NSEW, padx=20, pady=30)
        
        self.scanning_btn = tk.Button(master, text="Port Scanning", command=self.scanning_com, width=20, height=5)
        self.scanning_btn.grid(column=1, row=4, sticky=tk.NSEW, padx=20, pady=30)

        self.close_btn = tk.Button(master, text="Quit", command=self.quit_com, width=20, height=5)
        self.close_btn.grid(column=2, row=4, sticky=tk.NSEW, padx=20, pady=30)

    def down_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Down Detection")
        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)
        tk.Grid.columnconfigure(root, 4, weight=1)
        tk.Grid.columnconfigure(root, 5, weight=1)        
        tk.Grid.rowconfigure(root, 0 ,weight=1)
        tk.Grid.rowconfigure(root, 1,weight=1)
        tk.Grid.rowconfigure(root, 2 ,weight=1)
        tk.Grid.rowconfigure(root, 3,weight=1)
        tk.Grid.rowconfigure(root, 4 ,weight=1)
        tk.Grid.rowconfigure(root, 5,weight=1)
        tk.Grid.rowconfigure(root, 6 ,weight=1)
        tk.Grid.rowconfigure(root, 7,weight=1)
        tk.Grid.rowconfigure(root, 8,weight=1)
        cls = down_detection(root)
        root.mainloop()
    
    def mapping_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Network Mapping")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3 ,weight=1)
        tk.Grid.rowconfigure(root, 4 ,weight=1)
        cls = Mapping(root)
        root.mainloop()

    def traffic_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Network_Traffic")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3 ,weight=1)
        tk.Grid.rowconfigure(root, 4,weight=1)
        cls = Network_Traffic(root)
        root.mainloop()
    
    def packets_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Packet Scan")
        #root.geometry("500x600")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3 ,weight=1)
        tk.Grid.rowconfigure(root, 4,weight=1)
        tk.Grid.rowconfigure(root, 5,weight=1)
        cls = Packet_Scanning(root)
        root.mainloop()
    
    def scanning_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Port Scaning")
        #root.geometry("500x600")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3 ,weight=1)
        tk.Grid.rowconfigure(root, 4,weight=1)
        cls = Port_Scanning(root)
        root.mainloop()
    
    def quit_com(self):
        self.master.destroy()
        plt.close()
        quit()

class Mapping:
    def __init__(self, master):
        self.master = master

        self.label = tk.Label(text="Network Mapping", font=20)
        self.label.grid(column=1, row=1, sticky=tk.NSEW, padx=20, pady=30)

        self.start_btn = tk.Button(master, text = 'Start', width=30, height=5, command = self.threading_scan)
        self.start_btn.grid(row=2, column=1, sticky=tk.NSEW, padx=20, pady=30)

        self.stop_btn = tk.Button(master, text= "Close", width=30, height=5, command=self.close_com)
        self.stop_btn.grid(row=3, column=1, sticky=tk.NSEW, padx=20, pady=30)

    def threading_scan(self):
        try:
            self.Show_btn.destroy()
            plt.close()
        except:
            pass
        start_scan = threading.Thread(target=self.start_com)
        start_scan.setName("Mapping Thread")
        start_scan.start()
        self.lable = tk.Label(master, text="Scan Started", font=20)
        self.lable.grid(column=1, row=4, sticky=tk.NSEW, padx=20, pady=30)

    def start_com(self):
        print("Scanning")        
        Scanner = nmap.PortScanner()
        Scanner.scan(hosts="192.168.1.0/24", arguments="-sn")
        host_list = [(x, Scanner[x]["status"]["state"], Scanner[x].hostname()) for x in Scanner.all_hosts()]
        plt.figure(1, figsize=(10,10))
        plt.title("Network Map")
        plt.margins(x=0.5, y=0.5)
        G = nx.Graph()
        for host, status, name in host_list:
            if "192.168.1.254" in host:
                name = "Router"
            if name == "":
                name = "N/A"
            G.add_node("IP: {0} \nHostname: {1}".format(host, name))

        for a in G.nodes:
            if "192.168.1.254" in a:
                temp = a

        for a in G.nodes():
            if a == temp:
                pass
            else:
                G.add_edge(temp, a)

        nx.draw(G, with_labels=True, font_weight='bold')
        try:
            self.lable.destroy()
            self.Show_btn = tk.Button(master, text= "Show Map", width=30, height=5, command=plt.show)
            self.Show_btn.grid(row=4, column=1, sticky=tk.NSEW, padx=20, pady=30)
        except:
            pass

    def close_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Main Menu")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3,weight=1)
        tk.Grid.rowconfigure(root, 4 ,weight=1)
        cls = Main_Menu(root)
        root.mainloop()

class Network_Traffic:
    def __init__(self, master):
        self.master = master

        self.clicked = tk.StringVar()
        self.clicked.set("Ethernet")

        self.options = ["Ethernet", "Wifi"]

        self.lable = tk.Label(master, text="Network Traffic", font=20)
        self.lable.grid(row=1, column=1, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.start_btn = tk.Button(master, text="Start", command=self.start_com, width=30, height=5)
        self.start_btn.grid(row=2, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.stop_btn = tk.Button(master, text="Stop", command=self.stop_com, width=30, height=5)
        self.stop_btn.grid(row=2, column=2, padx=20, pady=30, sticky=tk.NSEW)

        self.close_btn = tk.Button(master, text="Close", command=self.close_com, width=30, height=5)
        self.close_btn.grid(row=4, column=1, columnspan=2, padx=20, pady=30)

        self.lable = tk.Label(master, text="Select Interface:", font=15)
        self.lable.grid(row=3, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.drop_down = tk.OptionMenu(master, self.clicked , *self.options)
        self.drop_down.grid(column=2, row=3, padx=20, pady=30)

    def close_com(self):
        self.kill_thread = False
        self.master.destroy()
        root = tk.Tk()
        root.title("Main Menu")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3,weight=1)
        tk.Grid.rowconfigure(root, 4 ,weight=1)
        cls = Main_Menu(root)
        root.mainloop()

    def start_com(self):
        global traf_root
        traf_root = tk.Toplevel(master)
        traf_root.geometry("500x500")
        tk.Grid.columnconfigure(traf_root, 1, weight=1)
        tk.Grid.rowconfigure(traf_root, 1 ,weight=1)
        tk.Grid.rowconfigure(traf_root, 2,weight=1)
        tk.Grid.rowconfigure(traf_root, 3,weight=1)
        tk.Grid.rowconfigure(traf_root, 4 ,weight=1)
        tk.Grid.rowconfigure(traf_root, 5 ,weight=1)
        tk.Grid.rowconfigure(traf_root, 6,weight=1)
        tk.Grid.rowconfigure(traf_root, 7,weight=1)
        tk.Grid.rowconfigure(traf_root, 8 ,weight=1)
        tk.Grid.rowconfigure(traf_root, 9 ,weight=1)
        tk.Grid.rowconfigure(traf_root, 10 ,weight=1)
        tk.Grid.rowconfigure(traf_root, 11 ,weight=1)
        my_label = tk.Label(traf_root, text="Live Traffic:", font=20)
        my_label.grid(column=1, row=1, padx=20, pady=30, sticky=tk.NSEW)
        net_traf_thread = threading.Thread(target=self.net_traf)
        net_traf_thread.setName("Ntwk Traf Thread")
        net_traf_thread.start()


    def stop_com(self):
        self.kill_thread = False
    
    def net_traf(self):
        self.kill_thread = True
        if self.clicked.get() == "Ethernet":
            option = 'eth'
        else:
            option = 'Wi-Fi'
        cap = pyshark.LiveCapture(interface=option)
        count = 0
        while self.kill_thread:
            var = []
            cap.sniff(timeout=5, packet_count=10)
            for packet in cap:
                try:
                    count += 1
                    var.append(("Packet Num: ", count, (packet.transport_layer), (packet.ip.src), " --> ", (packet.ip.dst), "Port:", (packet[packet.transport_layer].srcport), " Length:", packet.ip.len ))
                    for i in range(len(var)):
                        if self.kill_thread == False:
                            pass
                        else:   
                            Traf_label = tk.Label(traf_root, text = var[i])
                            Traf_label.grid(column=1, row=(i+3), padx=20, pady=5, sticky=tk.NSEW)
                except:
                    pass
                cap.clear()
        try:
            traf_root.destroy()
        except:
            pass

class Packet_Scanning:
    def __init__(self, master):
        self.master = master

        self.clicked = tk.StringVar()
        self.clicked.set("Ethernet")

        self.options = ["Ethernet", "Wifi"]

        self.font = tkFont.Font(family="Helvetica")

        self.lable = tk.Label(master, text="Network Packets", font=self.font, width=30, height=5)
        self.lable.grid(row=1, column=1, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.start_btn = tk.Button(master, text="Start", command=self.start_com, width=30, height=5, font=self.font)
        self.start_btn.grid(row=5, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.close_btn = tk.Button(master, text= "Close", width=30, height=5, command=self.close_com, font=self.font)
        self.close_btn.grid(row=5, column=2, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.timeout_lable = tk.Label(master, text="Timeout:", font=self.font, width=30, height=5)
        self.timeout_lable.grid(row=3, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.Timeout_entry = tk.Entry(master, font=self.font)
        self.Timeout_entry.grid(row=3, column=2, padx=20, pady=30)

        self.Num_lable = tk.Label(master, text="Number of Packets:", font=self.font, width=30, height=5)
        self.Num_lable.grid(row=2, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.Num_entry = tk.Entry(master, font=self.font)
        self.Num_entry.grid(column=2, row=2, padx=20, pady=30)

        self.lable = tk.Label(master, text="Select Interface:", font=15)
        self.lable.grid(row=4, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.drop_down = tk.OptionMenu(master, self.clicked , *self.options)
        self.drop_down.grid(column=2, row=4, padx=20, pady=30)

    def start_com(self):
        self.scan_thread = threading.Thread(target=self.Scan, daemon = True)
        self.scan_thread.start()

    def Scan(self):
        if self.clicked.get() == "Ethernet":
            option = 'eth'
        else:
            option = 'Wi-Fi'
        cap = pyshark.LiveCapture(interface=option)
        Num_Pack = self.Num_entry.get()
        timeout = self.Timeout_entry.get()
        self.Num_entry.delete(0, END)
        self.Timeout_entry.delete(0, END)
        if (timeout or Num_Pack) == "":
            messagebox.showwarning(title="Input Error", message="Timeout and Number of Packets Required!")
            return
        try:
            int(timeout)
            int(Num_Pack)
        except:
            messagebox.showwarning(title="Input Error", message="Timeout or Num_pack needs \nto be an intiger value!")
            return

        def info(text):
            messagebox.showinfo(title="Packet", message=text)

        def packet_function(packet):
            def func(x = packet):
                return info(x)
            self.but_dic[self.i] = tk.Button(self.but_root, text="Packet {0}".format(self.i), command=func, font=self.font)
            self.but_dic[self.i].grid(row=self.x, column=self.y, padx=5, pady=5, sticky=tk.NSEW)
            self.i+=1
            self.y+=1
            if self.y % 10 == 0:
                self.y = 0
                self.x +=1
                tk.Grid.rowconfigure(self.but_root, self.x ,weight=1)

        self.but_dic = {}
        self.y = 0
        self.x = 0
        self.i = 1                
        self.but_root = tk.Tk()
        self.but_root.title("Packets")

        try:
            cap.apply_on_packets(packet_function, timeout=int(timeout), packet_count=int(Num_Pack))
        except:
            pass

        tk.Grid.rowconfigure(self.but_root, 0 ,weight=1)

        for i in range(10):
            tk.Grid.columnconfigure(self.but_root, i, weight=1)
        
        close_button = tk.Button(self.but_root, text="Close", command=self.close_packet, font=self.font)
        close_button.grid(row=self.x+1, column=4, columnspan=2, padx=5, pady=5, sticky=tk.NSEW)
        tk.Grid.rowconfigure(self.but_root, self.x+1, weight=1)
    
    def close_packet(self):
        self.but_root.destroy()
        self.master.destroy()
        root = tk.Tk()
        root.title("Packet Scan")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3 ,weight=1)
        tk.Grid.rowconfigure(root, 4,weight=1)
        tk.Grid.rowconfigure(root, 5,weight=1)
        cls = Packet_Scanning(root)
        root.mainloop()

    def close_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Main Menu")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3,weight=1)
        tk.Grid.rowconfigure(root, 4 ,weight=1)
        cls = Main_Menu(root)
        root.mainloop()

class down_detection:
    def __init__(self, master):
        self.master = master

        self.path = "Text_Files\\"
        self.IPfile = "IPs.txt"
        self.Emailfile = "Emails.txt"

        self.font = tkFont.Font(family="Helvetica")

        self.lable = tk.Label(master, text="Down Detection", font=self.font)
        self.lable.grid(row=0, column=3, padx=20, pady=30, sticky=tk.NSEW)

        self.lable = tk.Label(master, text="Current IPs:", font=self.font)
        self.lable.grid(row=1, column=4, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.lable = tk.Label(master, text="Current Emails:", font=self.font)
        self.lable.grid(row=5, column=4, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.Email_lable = tk.Label(master, text=",\n".join(self.fileread(self.path, self.Emailfile)), font=self.font)
        self.Email_lable.grid(row=6, column=4, columnspan=2, rowspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.IP_lable = tk.Label(master, text=",\n".join(self.fileread(self.path, self.IPfile)), font=self.font)
        self.IP_lable.grid(row=2, column=4, columnspan=2, rowspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.lable = tk.Label(master, text="Add or Remove IP", font=self.font)
        self.lable.grid(row=1, column=1, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.lable = tk.Label(master, text="IP:", font=self.font)
        self.lable.grid(row=2, column=0, padx=20, pady=30, sticky=tk.NSEW)

        self.IP_entry = tk.Entry(master, font=self.font)
        self.IP_entry.grid(row=2, column=1, columnspan=2, padx=20, pady=30)

        self.start_btn = tk.Button(master, text="Add", command=self.add_IP, font=self.font)
        self.start_btn.grid(row=3, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.close_btn = tk.Button(master, text= "Remove", command=self.remove_IP, font=self.font)
        self.close_btn.grid(row=3, column=2, padx=20, pady=30, sticky=tk.NSEW)

        self.lable = tk.Label(master, text="Add or Remove Email", font=self.font)
        self.lable.grid(row=5, column=1, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.lable = tk.Label(master, text="Email:", font=self.font)
        self.lable.grid(row=6, column=0, padx=20, pady=30, sticky=tk.NSEW)

        self.Email_entry = tk.Entry(master, font=self.font)
        self.Email_entry.grid(row=6, column=1, columnspan=2, padx=20, pady=30)

        self.start_btn = tk.Button(master, text="Add", command=self.add_Email, font=self.font)
        self.start_btn.grid(row=7, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.close_btn = tk.Button(master, text= "Remove", command=self.remove_Email, font=self.font)
        self.close_btn.grid(row=7, column=2, padx=20, pady=30, sticky=tk.NSEW)

        self.close_btn = tk.Button(master, text= "Close", command=self.close_com, font=self.font)
        self.close_btn.grid(row=8, column=3, padx=20, pady=30, sticky=tk.NSEW)
    
    def RemoveLine(self, path, file, item):
        a_file = open(path + file, "r")
        lines = a_file.readlines()
        a_file.close()
        new_file = open(path + file, "w")
        for line in lines:
            if line.strip("\n") != item:
                new_file.write(line)
        new_file.close()

    def AddLine(self, path, file, item):
        a_file = open(path + file, "a+")
        a_file.write(item + "\n")
        a_file.close()

    def fileread(self, path, file):
        a_file = open(path + file, "r")
        Temp_list = []
        for line in a_file:
            stripped_line = line.strip()
            line_list = stripped_line.split()
            Temp_list.append(line_list[0])
        a_file.close()
        temp = ",\n".join(Temp_list)
        return(Temp_list)

    def FileSearch(self, path, file, item):
        temp_list = self.fileread(path, file)
        self.IP_entry.delete(0, END)
        self.Email_entry.delete(0, END)
        for a in temp_list:
            if item == a:
                return(1)
        return(0)

    def add_IP(self):
        #found regex at geeks for geeks
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        Entry_Data = self.IP_entry.get()
        if(re.fullmatch(regex, Entry_Data)):
            if (self.FileSearch(self.path, self.IPfile, Entry_Data)) == 0:
                self.AddLine(self.path, self.IPfile, Entry_Data)
                self.IP_lable.destroy()
                self.IP_lable = tk.Label(master, text=",\n".join(self.fileread(self.path, self.IPfile)), font=self.font)
                self.IP_lable.grid(row=2, column=4, columnspan=2, rowspan=2, padx=20, pady=30, sticky=tk.NSEW)
            else:
                messagebox.showwarning(title="Error", message="Item already in the list!")
        else:
            messagebox.showwarning(title="Error", message="IP not a valid format!")

    def remove_IP(self):
        Entry_Data = self.IP_entry.get()
        if (self.FileSearch(self.path, self.IPfile, Entry_Data)) == 1:
            self.RemoveLine(self.path, self.IPfile, Entry_Data)
            self.IP_lable.destroy()
            self.IP_lable = tk.Label(master, text=",\n".join(self.fileread(self.path, self.IPfile)), font=self.font)
            self.IP_lable.grid(row=2, column=4, columnspan=2, rowspan=2, padx=20, pady=30, sticky=tk.NSEW)
        else:
            messagebox.showwarning(title="Error", message="Item not in the list!")      
    
    def add_Email(self):
        #found regex at geeks for geeks
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        Entry_Data = self.Email_entry.get()
        if(re.fullmatch(regex, Entry_Data)):
            if self.FileSearch(self.path, self.Emailfile, Entry_Data) == 0:
                self.AddLine(self.path, self.Emailfile, Entry_Data)
                self.Email_lable.destroy()
                self.Email_lable = tk.Label(master, text=",\n".join(self.fileread(self.path, self.Emailfile)), font=self.font)
                self.Email_lable.grid(row=6, column=4, columnspan=2, rowspan=2, padx=20, pady=30, sticky=tk.NSEW)
            else:
                messagebox.showwarning(title="Error", message="Item already in the list!")
        else:
            messagebox.showwarning(title="Error", message="Email is not valid format!")

    def remove_Email(self):
        Entry_Data = self.Email_entry.get()
        if self.FileSearch(self.path, self.Emailfile, Entry_Data) == 1:
            self.RemoveLine(self.path, self.Emailfile, Entry_Data)
            self.Email_lable.destroy()
            self.Email_lable = tk.Label(master, text=",\n".join(self.fileread(self.path, self.Emailfile)), font=self.font)
            self.Email_lable.grid(row=6, column=4, columnspan=2, rowspan=2, padx=20, pady=30, sticky=tk.NSEW)
        else:
            messagebox.showwarning(title="Error", message="Item not in the list!")

    def close_com(self):
        self.master.destroy()
        root = tk.Tk()
        root.title("Main Menu")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3,weight=1)
        tk.Grid.rowconfigure(root, 4 ,weight=1)
        cls = Main_Menu(root)
        root.mainloop() 

class Port_Scanning:
    def __init__(self, master):
        self.master = master

        self.scan_type = tk.StringVar()
        self.scan_type.set("Quick Scan")

        self.options = ["Quick Scan", "Regular Scan", "Intense Scan"]

        self.font = tkFont.Font(family="Helvetica")

        self.lable = tk.Label(master, text="Port Scanning", font=self.font, width=30, height=5)
        self.lable.grid(row=1, column=1, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.start_btn = tk.Button(master, text="Start", command=self.Start_Com , width=30, height=5, font=self.font)
        self.start_btn.grid(row=4, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.close_btn = tk.Button(master, text= "Close", width=30, height=5, command=self.close_com, font=self.font)
        self.close_btn.grid(row=4, column=2, columnspan=2, padx=20, pady=30, sticky=tk.NSEW)

        self.Scan_lable = tk.Label(master, text="Scan Type", font=self.font, width=30, height=5)
        self.Scan_lable.grid(row=3, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.IP_lable = tk.Label(master, text="IP:", font=self.font, width=30, height=5)
        self.IP_lable.grid(row=2, column=1, padx=20, pady=30, sticky=tk.NSEW)

        self.drop_down = tk.OptionMenu(master, self.scan_type , *self.options)
        self.drop_down.grid(column=2, row=3, padx=20, pady=30)    
        
        self.IP_entry = tk.Entry(master, font=self.font)
        self.IP_entry.grid(column=2, row=2, padx=20, pady=30)

    def Start_Com(self):
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        IP = self.IP_entry.get()
        if IP == "":
            messagebox.showwarning(title="Error", message="IP not a valid format!")
            return
        else:
            if(re.fullmatch(regex, IP)):
                threading.Thread(target=self.Scan).start()    
            else:
                messagebox.showwarning(title="Error", message="IP not a valid format!")   
                return

    def Scan(self):
        Scan_Type = self.scan_type.get()
        IP = self.IP_entry.get()
        self.IP_entry.delete(0, END)
        Scanner = nmap.PortScanner()
        if Scan_Type == "Quick Scan":
            Scanner.scan(hosts=IP, arguments="-T4 -F", timeout=3600)
            try:
                proto_list = [Scanner[IP].all_protocols()]
                result_root = tk.Tk()
                for a in proto_list:
                    port_list = [(x, Scanner[IP][a[0]][x]['name'], a) for x in Scanner[IP]['tcp'].keys()]
                label = tk.Label(result_root, text="Open Ports")
                label.grid(row=0, column=0)
                i=1
                for port, name, proto in port_list:
                    tk.Grid.rowconfigure(result_root, i ,weight=1)
                    port_lable = tk.Label(result_root, text=("Port: {0}/{2} Service: {1}".format(port, name, proto[0])))
                    port_lable.grid(column=0, row=i)
                    i+=1
                close_but = tk.Button(result_root, text="Close", command=result_root.destroy)
                close_but.grid(column=0, row=i+1)
                tk.Grid.columnconfigure(result_root, 0 ,weight=1)
            except:
                print("Request Timed Out")
                
        elif Scan_Type == "Regular Scan":
            Scanner.scan(hosts=IP, arguments="", timeout=3600)
            result_root = tk.Tk()
            try:
                proto_list = [Scanner[IP].all_protocols()]
                for a in proto_list:
                    port_list = [(x, Scanner[IP][a[0]][x]['name'], a) for x in Scanner[IP]['tcp'].keys()]
                label = tk.Label(result_root, text="Open Ports")
                label.grid(row=0, column=0)
                i=1
                for port, name, proto in port_list:
                    tk.Grid.rowconfigure(result_root, i ,weight=1)
                    port_lable = tk.Label(result_root, text=("Port: {0}/{2} Service: {1}".format(port, name, proto[0])))
                    port_lable.grid(column=0, row=i)
                    i+=1
                close_but = tk.Button(result_root, text="Close", command=result_root.destroy)
                close_but.grid(column=0, row=i+1)
                tk.Grid.columnconfigure(result_root, 0 ,weight=1)
            except:
                print("Request Timed Out")

        elif Scan_Type == "Intense Scan":
            Scanner.scan(hosts=IP, arguments="-T4 -A -v", timeout=3600)
            try:
                result_root = tk.Tk()
                proto_list = [Scanner[IP].all_protocols()]
                for a in proto_list:
                    port_list = [(x, Scanner[IP][a[0]][x]['name'], a) for x in Scanner[IP]['tcp'].keys()]
                label = tk.Label(result_root, text="Open Ports")
                label.grid(row=0, column=0)
                i=1
                for port, name, proto in port_list:
                    tk.Grid.rowconfigure(result_root, i ,weight=1)                    
                    port_lable = tk.Label(result_root, text=("Port: {0}/{2} Service: {1}".format(port, name, proto[0])))
                    port_lable.grid(column=0, row=i)
                    i+=1
                os_lable = tk.Label(result_root, text=("OS: {0} Accuracy: {1}%".format(Scanner[IP]['osmatch'][0]['name'], Scanner[IP]['osmatch'][0]['accuracy'])))
                os_lable.grid(column=0, row=i)
                close_but = tk.Button(result_root, text="Close", command=result_root.destroy)
                close_but.grid(column=0, row=i+1)
                tk.Grid.columnconfigure(result_root, 0 ,weight=1)
            except:
                print("Request Timed Out")


    def close_com(self):
        self.master.destroy()
        root = tk.Tk()
        closed = True
        root.title("Main Menu")
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.rowconfigure(root, 1 ,weight=1)
        tk.Grid.rowconfigure(root, 2,weight=1)
        tk.Grid.rowconfigure(root, 3,weight=1)
        tk.Grid.rowconfigure(root, 4 ,weight=1)
        cls = Main_Menu(root)
        root.mainloop() 

def start_ping():
    import Ping

if __name__ == "__main__" :
    threading.Thread(target=start_ping).start()
    root = tk.Tk()
    root.title("Main Menu")
    tk.Grid.columnconfigure(root, 1, weight=1)
    tk.Grid.columnconfigure(root, 2, weight=1)
    tk.Grid.rowconfigure(root, 1 ,weight=1)
    tk.Grid.rowconfigure(root, 2,weight=1)
    tk.Grid.rowconfigure(root, 3,weight=1)
    tk.Grid.rowconfigure(root, 4 ,weight=1)
    cls = Main_Menu(root)
    root.mainloop() 