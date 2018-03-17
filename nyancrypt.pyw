import pickle, math, fractions, random, sys, time, os
import tkinter as tk, tkinter.filedialog as filedialog
import tkinter.messagebox as message_box
from tkinter import PhotoImage; from PIL import Image as PIL_IMAGE, ImageTk as TK_IMAGE; 
from tkinter.ttk import Progressbar as tk_progress

def coprime(a, b):
    return fractions.gcd(a, b) == 1;

def rabinMiller(n_prime):
    s = n_prime - 1; t = 0;
    while s % 2 == 0:
        s = s//2; t+=1
    for trials in range(5):
        a = random.randrange(2, n_prime-1); v = pow(a, s, n_prime)
        if v != 1:
            i = 0
            while v != (n_prime - 1):
                if i==t - 1: return False;
                else: i = i +1; v = (v**2)%n_prime;
    return True;

def isPrime(n):
    if n % 2 == 0: return False;
    lowPrimes=[3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
                   ,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
                   ,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
                   ,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
                   ,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
                   ,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
                   ,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
                   ,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
                   ,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
                   ,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]
    if n in lowPrimes: return False;
    for num in lowPrimes:
        if n % num == 0: return False;
    return rabinMiller(n);

def generateLargePrime(k):
    #k is desired bit len
    r = 100*(math.log(k, 2)+1); r_ = r
    while r > 0:
        n = random.randrange(2**(k-1), 2**(k)); r-=1
        if isPrime(n)==True: return n;
    return ("Failure after "+str(r_)+" tries.");

def egcd(a, b):
    if a == 0: return (b, 0, 1);
    else: g, y, x = egcd(b % a, a); return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1: raise Exception('modular inverse does not exist!');
    else: return x % m;

def gen_keys(keysize):
    p = generateLargePrime(keysize);q = generateLargePrime(keysize);n = p * q;
    while True:
        e = random.randrange(2 ** (keysize - 1), 2 ** (keysize));
        if fractions.gcd(e, (p - 1) * (q - 1)) == 1:break;
    d = modinv(e, (p-1)*(q-1));publicKey = (hex(n), hex(e));privateKey = (hex(n), hex(d))
    return {'prv':privateKey,'pub':publicKey};



def SavePklFile(data, d_type, extension):
    file=filedialog.asksaveasfile(mode='wb',filetypes=[(extension+"file","*."+extension),("All files","*.*")],defaultextension="."+extension, title="Saving... "+d_type)
    try: pickle.dump(data, file); file.close(); return 0;
    except: return 1;

def LoadPklFile(d_type, extension):
    file=filedialog.askopenfilename(filetypes=[(extension,"*."+extension),("All files","*.*")], title="Open ::: @rsa ::: "+d_type+" file.")
    try: return pickle.load(open(file, "rb")), file;
    except: return None;

def LoadByteFile(d_type, extension):
    file=filedialog.askopenfilename(filetypes=[(extension,"*."+extension),("All files","*.*")], title="Open ::: @rsa :::"+d_type+" file.")
    try: return file;
    except: return None;

def LoadDirectory():
    return filedialog.askdirectory();

def rsa_bytes(pk, raw_bytes, mode, maxBytes):
    out=[]
    byte_count=len(raw_bytes); item=1
    main_perc=0; perc=0
    window = percentage_window()
    if mode=="encrypt":
        for byte in raw_bytes:
            window.update()
            perc = (item/byte_count)*100;item+=1
            if perc > main_perc: window.increment(perc-main_perc); main_perc=perc;
            c = pow(byte, pk[1], pk[0])
            byteArray= c.to_bytes(maxBytes, "big")
            for byte in byteArray:
                out.append(int(byte))
        window.destroy(); message_box.showinfo(title="Encryption finished!", message="The file has been succesfully encrypted"); return bytes(out);
    if mode=="decrypt":
        k=1
        byte_array=[]
        for byte in raw_bytes:
            window.update()
            perc = int((item/byte_count)*100);item+=1
            if perc > main_perc: window.increment(perc-main_perc); main_perc=perc;
            if k==maxBytes:
                byte_array.append(byte); k+=1
                c = int.from_bytes(byte_array, "big")
                m = pow(c, pk[1], pk[0])
                if m > 255: window.destroy(); return [256];
                out.append(m)
                byte_array=[]; k=1; continue;
            byte_array.append(byte); k+=1
        window.destroy(); message_box.showinfo(title="Decryption finished!", message="The file has been succesfully decrypted"); return bytes(out);

def byte_worker(key=None, raw_file=None, mode="encrypt"):
    global backupDir
    raw = open(raw_file, "rb").read()
    if backupDir != r"C:// ¯\_( ͡ᵔ ͜ʖ ͡ᵔ)_/¯":
        try:
            bkp = open(os.path.join(backupDir, raw_file), "wb")
            bkp.write(raw); bkp.close()
        except:
            message_box.showerror("WARN","WARN ::: NO VALID BACKUP DIRECTORY SET!")
    ki = int(key[0], 16), int(key[1], 16)
    maxbyte = sys.getsizeof(ki[0])
    out = rsa_bytes(ki, raw, mode, maxbyte)
    for i in range(len(out)):
        if out[i] > 255: print("BIT OUT OF RANGE"); return 1;
    open(raw_file,"wb").write(out)
    return 0;

class percentage_window(tk.Toplevel):

    def __init__(self, *args ,**kwargs):
        tk.Toplevel.__init__(self,*args,**kwargs); imgico = tk.PhotoImage(file="icon.gif"); self.title("Working on it..."); self.tk.call('wm', 'iconphoto', self._w, imgico); self.progress = tk_progress(self, orient="horizontal", length=400, mode="determinate"); self.progress.pack()

    def start(self):
        self.progress['value']=0; self.progress['maximum']=100

    def increment(self, amount):
        self.progress['value']+=amount
        

class top_level(tk.Tk):

    def __init__(self, *args, **kwargs):
        global backupDir

        backupDir = r"C:// ¯\_( ͡ᵔ ͜ʖ ͡ᵔ)_/¯"
        tk.Tk.__init__(self, *args, **kwargs); imgico = tk.PhotoImage(file="icon.gif"); self.title("Nyan crypt - v1.0"); self.tk.call('wm', 'iconphoto', self._w, imgico);
        self.container = tk.Frame(self); self.container.grid(row=1, column=0); self.configure(bg="#014479"); 
        self.banner = PIL_IMAGE.open("nyan_cat.jpg")
        self.raise_page('main')

    def raise_page(self, p_val):
        self.container.destroy(); self.container = tk.Frame(self, bg="#014479"); self.container.grid(row=1, column=0);
        if p_val == 'generate_key': self.current_page = generate_key_page(self, self.container)
        if p_val == 'encrypt': self.current_page = encrypt_page(self, self.container)
        if p_val == 'decrypt': self.current_page = decrypt_page(self, self.container)
        if p_val == 'main': self.current_page = main_menu(self, self.container)

    def resize_bnr(self):
        bnr_native=(640, 125)
        self.update(); h_div = bnr_native[0]/bnr_native[1]
        self.banner_resized = TK_IMAGE.PhotoImage(self.banner.resize((int(self.winfo_width()), int(self.winfo_width()/h_div)), PIL_IMAGE.ANTIALIAS));
        self.banner_label = tk.Label(self, image=self.banner_resized, border=0, bg="#ffffff")
        self.banner_label.grid(row=0, column=0, sticky="nesw", pady=(5,0))
        self.resizable(False, False)

class main_menu():

    def __init__(self, master, container, *args, **kwargs):
        self.master = master
        global backupDir
        self.backup = tk.StringVar()
        self.backup.set(backupDir)
        
        generate_button = tk.Button(container, text="Generate keys", command=lambda: self.gen_key(), width=20, font="Helvitica 12 bold")
        encrypt_button = tk.Button(container, text="Encrypt file", command=lambda: self.encrypt(), width=20, font="Helvitica 12 bold")
        decrypt_button = tk.Button(container, text="Decrypt file", command=lambda: self.decrypt(), width=20, font="Helvitica 12 bold")
        
        set_backup_dir = tk.Button(container, text="Back-up dir: ", command= lambda: self.bkp(), width=10, anchor="w", font="Helvitica 12 bold")
        bkp_label1 = tk.Label(container,textvariable=self.backup, anchor="w", relief=tk.SUNKEN, font="Helvitica 18 bold")
        title_label = tk.Label(container, text="~NyanCrypt v1.0~", font="Helvitica 32 bold", justify=tk.CENTER, anchor=tk.CENTER, bg="#D3D3D3")

        seperator1 = tk.Frame(container, bg="#1e1e1e", height=5, borderwidth=0)
        seperator2 = tk.Frame(container, bg="#1e1e1e", height=5, borderwidth=0)
        seperator3 = tk.Frame(container, bg="#1e1e1e", height=5, borderwidth=0)

        #GRID (0, 1)
        seperator3.grid(row=0, column=0, columnspan=5, sticky="nesw")
        #GRID (1, 0)
        title_label.grid(row=1, column=0, columnspan=6, sticky="nesw")
        #GRID (2, 1)
        seperator2.grid(row=2, column=1, columnspan=5, sticky="nesw")
        #GRID (3, 1)
        generate_button.grid(row=3, column=1, sticky="nesw", padx=10, pady=10);
        #GRID (3, 3)
        encrypt_button.grid(row=3, column=3, sticky="nesw", padx=10, pady=10);
        #GRID (3, 5)
        decrypt_button.grid(row=3, column=5, sticky="nesw", padx=10, pady=10);
        #GRID (4, 1)
        seperator1.grid(row=4, column=1, columnspan=5, sticky="nesw")
        #GRID (5, 1)
        set_backup_dir.grid(row=5, column=1, sticky="e", pady=10, padx=10);
        #GRID (5, 3)
        bkp_label1.grid(row=5, column=3, sticky="ew", columnspan=5, padx = (0, 10))
        
        
        master.resize_bnr()

    def gen_key(self):
        self.master.raise_page('generate_key')

    def encrypt(self):
        self.master.raise_page('encrypt')

    def decrypt(self):
        self.master.raise_page('decrypt')

    def bkp(self):
        global backupDir
        backupDir = LoadDirectory()
        self.backup.set(backupDir)

class generate_key_page():

    def __init__(self, master, container, *args, **kwargs):
        self.master=master;self.keyvar = tk.StringVar();self.keyvar.set('1024')

        generate_button = tk.Button(container, text="Generate key", command=lambda: self.generate(), font="Helvitica 12 bold");
        key_size = tk.Entry(container, textvariable=self.keyvar, font="Helvitica 12 bold");
        key_size_label = tk.Label(container, text="Key-size:", font="Helvitica 12 bold");
        
        b1 = tk.Button(container, text="Go back", command=lambda: self.master.raise_page('main'), font="Helvitica 12 bold");

        generate_button.grid(row=2, column=1, columnspan=2, pady=(0,10), padx=5, sticky="ew");

        #GRID (1, 0)
        key_size_label.grid(row=1, column=0, sticky="e", pady=10, padx=5)
        #GRID (1, 1)
        key_size.grid(row=1, column=1, padx=5, pady=10);
        #GRID (2, 0)
        b1.grid(row=2, column=0, pady=(0,10), padx=5, sticky="ew")
        
        master.resize_bnr()

    def generate(self):
        size = self.keyvar.get()
        try: int(size)
        except: return message_box.showerror("String in key size!","Keysize must be an integer not a string!");
        size = int(size)
        if size < 16 or size > 8192: return message_box.showerror("Invalid keysize!", "Keysize must be an integer (where size % 8 = 0) above 16 and below 8192!");
        if size % 8 != 0: return message_box.showerror("Invalid keysize!", "Keysize must be an integer where size % 8 = 0")
        while True:
            try: keys = gen_keys(size); break;
            except: pass;
        if SavePklFile(keys['prv'], "@rsa Private key", "pv_key") == 1: message_box.showerror("File saving cancelled!","File saving has been cancelled!"); return None;
        if SavePklFile(keys['pub'], "@rsa Public key", "pb_key") == 1: message_box.showerror("File saving cancelled!","File saving has been cancelled!"); return None;
        self.master.raise_page('main')

class encrypt_page():

    def __init__(self, master, container, *args, **kwargs):
        self.master=master;self.pub_file = tk.StringVar(); self.byte_file = tk.StringVar();self.pub_file.set(''); self.byte_file.set('');
        self.gotPub=False; self.gotByte=False;

        self.b1 = tk.Button(container, text="Browse for public key file:", command=lambda: self.loadPubkey(), font="Helvitica 12 bold")
        self.b2 = tk.Button(container, text="Browse for file to encrypt:", command=lambda: self.loadByteFile(), font="Helvitica 12 bold")
        self.b3 = tk.Button(container, text="Encrypt", command=lambda: self.initWorker(), state=tk.DISABLED, font="Helvitica 12 bold")
        self.b4 = tk.Button(container, text="Go back", command=lambda: self.master.raise_page('main'), font="Helvitica 12 bold")

        self.l1 = tk.Label(container, textvariable=self.pub_file, width=30, font="Helvitica 12 bold");
        self.l2 = tk.Label(container, textvariable=self.byte_file, width=30, font="Helvitica 12 bold")

        #GRID (0,0)
        self.b1.grid(row=0, column=0, padx=5, pady=5, sticky="nesw");
        #GRID (0, 1)
        self.l1.grid(row=0, column=1, columnspan=2, pady=5, sticky="nesw");
        #GRID (1, 0)
        self.b2.grid(row=1, column=0, padx=5, pady=5, sticky="nesw");
        #GRID (1, 1)
        self.l2.grid(row=1, column=1, columnspan=2, pady=5, sticky="nesw");
        #GRID (2, 0)
        self.b4.grid(row=2, column=0, pady=5, sticky="nesw", padx=5)
        #GRID (2, 1)
        self.b3.grid(row=2, column=1, columnspan=2, pady=5, sticky="nesw");
        master.resize_bnr()

    def loadPubkey(self):
        ret = LoadPklFile("Public Key","pb_key")
        if ret == None: message_box.showerror("Invalid public key selected!","This file does not contain a valid public key!"); return None;
        self.pub_key=ret[0];self.pub_file.set(ret[1])
        self.gotPub=True
        if self.gotPub==True and self.gotByte==True:
            self.b3.config(state=tk.NORMAL)

    def loadByteFile(self):
        ret = LoadByteFile("File to encrypt", "*")
        if ret == None: message_box.showerror("No file selected!", "Please select a file!"); return None;
        self.bytes=ret;self.byte_file.set(ret)
        self.gotByte=True
        if self.gotPub==True and self.gotByte==True:
            self.b3.config(state=tk.NORMAL)

    def initWorker(self):
        if byte_worker(self.pub_key, self.bytes, "encrypt")==1: message_box.showerror("Encryption failed!!!", "Encryption service failed - returning to encryption page"); return None;
        self.master.raise_page('main')

class decrypt_page():

    def __init__(self, master, container, *args, **kwargs):
        self.master=master;self.prv_file = tk.StringVar(); self.byte_file = tk.StringVar();self.prv_file.set(''); self.byte_file.set('')
        self.gotPrv=False; self.gotByte=False;

        self.b1 = tk.Button(container, text="Browse for private key file:", command=lambda: self.loadPrvkey(), font="Helvitica 12 bold")
        self.b2 = tk.Button(container, text="Browse for file to decrypt :", command=lambda: self.loadByteFile(), font="Helvitica 12 bold")
        self.b3 = tk.Button(container, text="Decrypt", command=lambda: self.initWorker(), state=tk.DISABLED, font="Helvitica 12 bold")
        self.b4 = tk.Button(container, text="Go back", command=lambda: self.master.raise_page('main'), font="Helvitica 12 bold")

        self.l1 = tk.Label(container, textvariable=self.prv_file, width=30, font="Helvitica 12 bold");
        self.l2 = tk.Label(container, textvariable=self.byte_file, width=30, font="Helvitica 12 bold")

        #GRID (0,0)
        self.b1.grid(row=0, column=0, padx=5, pady=5, sticky="nesw");
        #GRID (0, 1)
        self.l1.grid(row=0, column=1, columnspan=2, pady=5, sticky="nesw");
        #GRID (1, 0)
        self.b2.grid(row=1, column=0, padx=5, pady=5, sticky="nesw");
        #GRID (1, 1)
        self.l2.grid(row=1, column=1, columnspan=2, pady=5, sticky="nesw");
        #GRID (2, 0)
        self.b4.grid(row=2, column=0, pady=5, sticky="nesw", padx=5)
        #GRID (2, 1)
        self.b3.grid(row=2, column=1, columnspan=2, pady=5, sticky="nesw");
        master.resize_bnr()

    def loadPrvkey(self):
        ret = LoadPklFile("Private Key","pv_key")
        if ret == None: message_box.showerror("Invalid private key selected!","This file does not contain a valid private key!"); return None;
        self.prv_key=ret[0];self.prv_file.set(ret[1])
        self.gotPrv=True
        if self.gotPrv==True and self.gotByte==True:
            self.b3.config(state=tk.NORMAL)

    def loadByteFile(self):
        ret = LoadByteFile("File to decrypt", "*")
        if ret == None: message_box.showerror("No file selected!", "Please select a file!"); return None;
        self.bytes=ret;self.byte_file.set(ret)
        self.gotByte=True
        if self.gotPrv==True and self.gotByte==True:
            self.b3.config(state=tk.NORMAL)

    def initWorker(self):
        if byte_worker(self.prv_key, self.bytes, "decrypt")==1: message_box.showerror("Decryption failed!!!", "Decryption service failed - returning to decryption page"); return None;
        self.master.raise_page('main')

gui = top_level()
gui.mainloop()
