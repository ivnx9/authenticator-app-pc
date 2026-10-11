import sys, subprocess, importlib.util, json, time, base64, urllib.parse, os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog


def resource_path(filename):
    """Find a bundled resource in a PyInstaller EXE or beside the .py file."""
    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        candidate = Path(bundle_dir) / filename
        if candidate.exists():
            return candidate
    return Path(__file__).resolve().parent / filename

# IMPORTANT: Never run pip from a packaged EXE. In a PyInstaller build,
# sys.executable points to this EXE, not to python.exe. Doing so can recursively
# launch more copies of the app. Install dependencies before building the EXE.
def need(mod, package=None):
    if importlib.util.find_spec(mod) is None:
        if getattr(sys, "frozen", False):
            raise RuntimeError(
                f"Required package '{package or mod}' was not bundled into this EXE.\n"
                "Rebuild after installing dependencies with Python."
            )
        subprocess.check_call([sys.executable, "-m", "pip", "install", package or mod])

for mod, pkg in [("pyotp", "pyotp"), ("qrcode", "qrcode[pil]"), ("cv2", "opencv-python"), ("PIL", "Pillow"), ("cryptography", "cryptography")]:
    try:
        need(mod, pkg)
    except Exception as e:
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror(
            "Setup error",
            f"Could not prepare dependency: {pkg}.\n"
            f"Run this in CMD while using the .py version:\n"
            f"{sys.executable} -m pip install {pkg}\n\nDetails: {e}"
        )
        r.destroy()
        raise

import pyotp, qrcode, cv2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Persistent storage outside the PyInstaller temporary extraction folder.
# On Windows this resolves to %LOCALAPPDATA%\Authenticator.
if os.name == "nt":
    _appdata = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    BASE = Path(_appdata) / "Authenticator"
else:
    BASE = Path.home() / ".local" / "share" / "Authenticator"
BASE.mkdir(parents=True, exist_ok=True)
DATA = BASE / "authenticator-data.json"
REMEMBER_FILE = BASE / "remember-this-pc.dpapi"

ENCRYPTED_FORMAT = "AuthenticatorPasswordVaultV1"
KDF_N = 2 ** 15
KDF_R = 8
KDF_P = 1


def derive_vault_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit vault key from a master password using scrypt."""
    import hashlib
    if len(password) < 12:
        raise ValueError("Use a master password with at least 12 characters.")
    # OpenSSL's default maxmem can be too small for N=32768, r=8 on Windows.
    # Explicitly allow 64 MiB for scrypt's working memory.
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=KDF_N,
        r=KDF_R,
        p=KDF_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )


def encrypt_vault(payload: dict, password: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_vault_key(password, salt)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, ENCRYPTED_FORMAT.encode("ascii"))
    return {
        "format": ENCRYPTED_FORMAT,
        "kdf": "scrypt",
        "kdf_n": KDF_N,
        "kdf_r": KDF_R,
        "kdf_p": KDF_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_vault(envelope: dict, password: str) -> dict:
    if envelope.get("format") != ENCRYPTED_FORMAT:
        raise ValueError(
            "This is not a master-password vault. Older DPAPI vaults need to be exported/imported before upgrading."
        )
    if envelope.get("kdf") != "scrypt" or envelope.get("kdf_n") != KDF_N:
        raise ValueError("Unsupported vault encryption parameters.")
    salt = base64.b64decode(envelope["salt"], validate=True)
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    key = derive_vault_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, ENCRYPTED_FORMAT.encode("ascii"))
    obj = json.loads(plaintext.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Vault contents are invalid.")
    return obj



def dpapi_protect(data: bytes) -> bytes:
    """Protect bytes using Windows DPAPI for the current Windows user."""
    if os.name != "nt":
        raise RuntimeError("Remember on this PC is available only on Windows.")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    source_buffer = ctypes.create_string_buffer(data)
    source = DATA_BLOB(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(source), "Authenticator remembered unlock",
        None, None, None, 0, ctypes.byref(output)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


def dpapi_unprotect(data: bytes) -> bytes:
    """Unprotect bytes using Windows DPAPI for the current Windows user."""
    if os.name != "nt":
        raise RuntimeError("Remember on this PC is available only on Windows.")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    source_buffer = ctypes.create_string_buffer(data)
    source = DATA_BLOB(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = DATA_BLOB()
    description = wintypes.LPWSTR()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source), ctypes.byref(description),
        None, None, None, 0, ctypes.byref(output)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
        if description:
            kernel32.LocalFree(description)


def save_remembered_password(password: str):
    protected = dpapi_protect(password.encode("utf-8"))
    temp = REMEMBER_FILE.with_suffix(".tmp")
    temp.write_bytes(protected)
    temp.replace(REMEMBER_FILE)


def get_remembered_password():
    if not REMEMBER_FILE.exists():
        return None
    try:
        return dpapi_unprotect(REMEMBER_FILE.read_bytes()).decode("utf-8")
    except Exception:
        # If the file cannot be opened (e.g. another Windows account), fail closed
        # and ask the user to enter the master password.
        return None


def password_prompt(root, vault_exists: bool):
    """Ask for a master password without persisting it."""
    result = {"password": None}
    win = tk.Toplevel(root)
    win.title("Unlock vault" if vault_exists else "Create vault password")
    win.configure(bg="#182232")
    win.resizable(False, False)
    # Do not make this dialog transient to the withdrawn root on Windows;
    # that can cause the password dialog to remain hidden.
    win.grab_set()
    win.lift()
    win.attributes("-topmost", True)
    win.after(250, lambda: win.attributes("-topmost", False))
    tk.Label(
        win,
        text="Unlock your vault" if vault_exists else "Create your vault password",
        font=("Segoe UI", 16, "bold"), bg="#182232", fg="#edf3fc"
    ).pack(anchor="w", padx=22, pady=(20, 8))
    hint = (
        "Enter your master password. Lost passwords cannot be recovered."
        if vault_exists else
        "Use at least 12 characters. This password cannot be recovered."
    )
    tk.Label(win, text=hint, bg="#182232", fg="#9aabc2", wraplength=350, justify="left").pack(
        anchor="w", padx=22, pady=(0, 12)
    )
    pw = tk.StringVar()
    entry = tk.Entry(win, textvariable=pw, show="•", bg="#10151f", fg="#edf3fc",
                     insertbackground="#edf3fc", relief="flat", width=38)
    entry.pack(padx=22, ipady=8)
    confirm = None
    if not vault_exists:
        tk.Label(win, text="Confirm password", bg="#182232", fg="#9aabc2").pack(
            anchor="w", padx=22, pady=(10, 3)
        )
        confirm = tk.StringVar()
        entry2 = tk.Entry(win, textvariable=confirm, show="•", bg="#10151f", fg="#edf3fc",
                          insertbackground="#edf3fc", relief="flat", width=38)
        entry2.pack(padx=22, ipady=8)
    error = tk.Label(win, text="", bg="#182232", fg="#ff8a8a", wraplength=350, justify="left")
    error.pack(anchor="w", padx=22, pady=(8, 0))

    def submit():
        password = pw.get()
        if len(password) < 12:
            error.config(text="Use at least 12 characters.")
            return
        if confirm is not None and password != confirm.get():
            error.config(text="Passwords do not match.")
            return
        if vault_exists:
            try:
                raw = json.loads(DATA.read_text(encoding="utf-8"))
                decrypt_vault(raw, password)
            except Exception:
                error.config(text="Could not unlock. Check the password or vault file.")
                return
        result["password"] = password
        win.destroy()

    buttons = tk.Frame(win, bg="#182232")
    buttons.pack(fill="x", padx=22, pady=18)
    tk.Button(buttons, text="Exit", command=win.destroy, bg="#222f42", fg="#edf3fc",
              relief="flat", padx=14, pady=7).pack(side="right")
    tk.Button(buttons, text="Continue", command=submit, bg="#28466f", fg="#edf3fc",
              relief="flat", padx=14, pady=7).pack(side="right", padx=(0, 8))
    entry.bind("<Return>", lambda _e: submit())
    win.protocol("WM_DELETE_WINDOW", win.destroy)
    entry.focus_set()
    root.wait_window(win)
    return result["password"]

BG="#10151f"; CARD="#182232"; CARD2="#222f42"; LINE="#304057"; FG="#edf3fc"; MUTED="#9aabc2"; BLUE="#79a9ff"; BLUE2="#28466f"; RED="#ff8a8a"

def vint(n):
    out=bytearray()
    while n>127: out.append((n&127)|128); n>>=7
    out.append(n); return bytes(out)
def fb(i,b): return vint((i<<3)|2)+vint(len(b))+b
def fv(i,n): return vint(i<<3)+vint(n)
def fs(i,s): return fb(i,str(s).encode())
def fields(data):
    p=0
    def vi():
        nonlocal p
        n=0; sh=0
        while p<len(data):
            b=data[p]; p+=1; n|=(b&127)<<sh
            if not b&128:return n
            sh+=7
            if sh>70: raise ValueError("Bad QR data")
        raise ValueError("Truncated QR data")
    while p<len(data):
        tag=vi(); no,wire=tag>>3,tag&7
        if wire==0: val=vi()
        elif wire==2:
            n=vi(); val=data[p:p+n]; p+=n
            if len(val)!=n: raise ValueError("Truncated QR data")
        elif wire==1: val=data[p:p+8]; p+=8
        elif wire==5: val=data[p:p+4]; p+=4
        else: raise ValueError("Unsupported QR data")
        yield no,wire,val
def b32(raw): return base64.b32encode(raw).decode().rstrip("=")
def migration_decode(raw):
    out=[]
    for no,w,val in fields(raw):
        if no!=1 or w!=2: continue
        d={"secret":b"","name":"","issuer":"","digits":1,"type":2}
        for k,ww,v in fields(val):
            if k==1 and ww==2:d["secret"]=v
            elif k==2 and ww==2:d["name"]=v.decode(errors="replace")
            elif k==3 and ww==2:d["issuer"]=v.decode(errors="replace")
            elif k==5 and ww==0:d["digits"]=v
            elif k==6 and ww==0:d["type"]=v
        if not d["secret"] or d["type"]==1: continue
        label=d["name"]; issuer=d["issuer"] or "Authenticator"; name=label
        if ":" in label:
            left,right=label.split(":",1)
            if not d["issuer"]: issuer=left or issuer
            name=right.strip() or label
        out.append({"issuer":issuer,"name":name or "Imported account","secret":b32(d["secret"]),"digits":8 if d["digits"]==2 else 6,"period":30})
    return out
def parse_qr(s):
    if s.startswith("otpauth-migration://"):
        q=urllib.parse.parse_qs(urllib.parse.urlparse(s).query)
        data=q.get("data",[""])[0]
        return migration_decode(base64.urlsafe_b64decode(data+"="*(-len(data)%4)))
    if s.startswith("otpauth://"):
        u=urllib.parse.urlparse(s); q=urllib.parse.parse_qs(u.query); label=urllib.parse.unquote(u.path.lstrip("/"))
        return [{"issuer":q.get("issuer",[label.split(":")[0] if ":" in label else "Authenticator"])[0],
                 "name":label.split(":",1)[-1].strip() or "Account","secret":q.get("secret",[""])[0].replace(" ","").upper(),
                 "digits":int(q.get("digits",[6])[0]),"period":int(q.get("period",[30])[0])}]
    raise ValueError("Unsupported QR type")
def decode_image(path):
    im=cv2.imread(str(path))
    if im is None: raise ValueError("Cannot open image")
    det=cv2.QRCodeDetector()
    try:
        ok, vals, pts, _=det.detectAndDecodeMulti(im)
        if ok and any(vals): return [v for v in vals if v]
    except Exception: pass
    val,_,_=det.detectAndDecode(im)
    if val:return [val]
    raise ValueError("No QR code found")
def migration_uri(accounts, idx, total):
    payload=bytearray()
    for a in accounts:
        secret=base64.b32decode(a["secret"].upper()+"="*((8-len(a["secret"])%8)%8))
        otp=fb(1,secret)+fs(2,f'{a.get("issuer","Authenticator")}:{a.get("name","Account")}')+fs(3,a.get("issuer","Authenticator"))+fv(4,1)+fv(5,2 if int(a.get("digits",6))==8 else 1)+fv(6,2)
        payload+=fb(1,otp)
    payload+=fv(2,1)+fv(3,total)+fv(4,idx)
    return "otpauth-migration://offline?data="+base64.urlsafe_b64encode(payload).decode().rstrip("=")

class App:
 def __init__(self,root,master_password):
    self.root=root
    self.master_password=master_password
    root.title("Authenticator — Local Vault")
    # The .ico is bundled inside the EXE with PyInstaller --add-data.
    # Do not look for it in BASE/LocalAppData or a temporary folder manually.
    try:
        icon_file = resource_path("authenticator.ico")
        if icon_file.is_file():
            root.iconbitmap(default=str(icon_file))
    except (tk.TclError, OSError):
        pass
    root.geometry("850x700"); root.minsize(620,520); root.configure(bg=BG)
    self.accounts=[]; self.widgets={}; self.search=tk.StringVar(); self.status=tk.StringVar(value="Master-password encrypted vault")
    st=ttk.Style(); st.theme_use("clam"); st.configure("Treeview",background=CARD,foreground=FG,fieldbackground=CARD,rowheight=36)
    head=tk.Frame(root,bg=BG); head.pack(fill="x",padx=24,pady=(22,15))
    tk.Label(head,text="◈",font=("Segoe UI",30,"bold"),bg=BG,fg=BLUE).pack(side="left",padx=(0,12))
    title=tk.Frame(head,bg=BG); title.pack(side="left",expand=True,fill="x")
    tk.Label(title,text="Authenticator",font=("Segoe UI",22,"bold"),bg=BG,fg=FG).pack(anchor="w")
    tk.Label(title,text="Offline codes · Master-password encrypted vault",font=("Segoe UI",9),bg=BG,fg=MUTED).pack(anchor="w")
    self.btn(head,"＋ Add",self.add,True).pack(side="left",padx=3)
    self.btn(head,"Import QR",self.import_qr).pack(side="left",padx=3)
    self.btn(head,"Export QR",self.export_qr).pack(side="left",padx=3)
    self.btn(head,"Settings",self.open_settings).pack(side="left",padx=3)
    bar=tk.Frame(root,bg=CARD,highlightbackground=LINE,highlightthickness=1); bar.pack(fill="x",padx=24,pady=(0,14))
    tk.Label(bar,text="LOCAL VAULT",bg=CARD,fg=BLUE,font=("Segoe UI",8,"bold")).pack(side="left",padx=12,pady=12)
    self.pathlabel=tk.Label(bar,text=str(DATA),bg=CARD,fg=MUTED,font=("Segoe UI",9),anchor="w"); self.pathlabel.pack(side="left",fill="x",expand=True)
    self.btn(bar,"Open folder",self.open_folder).pack(side="right",padx=7,pady=5)
    self.btn(bar,"Load JSON",self.load_other).pack(side="right",padx=2,pady=5)
    self.btn(bar,"Save now",self.save).pack(side="right",padx=2,pady=5)
    tools=tk.Frame(root,bg=BG); tools.pack(fill="x",padx=24,pady=(0,8))
    tk.Label(tools,text="YOUR ACCOUNTS",bg=BG,fg=MUTED,font=("Segoe UI",9,"bold")).pack(side="left")
    ent=tk.Entry(tools,textvariable=self.search,bg=CARD,fg=FG,insertbackground=FG,relief="flat",font=("Segoe UI",10),width=26); ent.pack(side="right",ipady=7,ipadx=7)
    self.search.trace_add("write",lambda *_:self.render())
    self.list=tk.Frame(root,bg=BG); self.list.pack(fill="both",expand=True,padx=24,pady=(0,12))
    foot=tk.Frame(root,bg=CARD,height=32); foot.pack(fill="x",side="bottom"); foot.pack_propagate(False)
    tk.Label(foot,textvariable=self.status,bg=CARD,fg=MUTED,font=("Segoe UI",9),anchor="w").pack(side="left",padx=24,fill="both",expand=True)
    self.load(silent=True); self.render(); self.tick(); root.protocol("WM_DELETE_WINDOW",self.close)
 def btn(self,parent,text,cmd,primary=False):
    return tk.Button(parent,text=text,command=cmd,bg=BLUE2 if primary else CARD2,fg=FG if primary else MUTED,activebackground=BLUE,activeforeground=BG,relief="flat",bd=0,padx=12,pady=8,font=("Segoe UI",9,"bold"),cursor="hand2")
 def open_settings(self):
    w = tk.Toplevel(self.root)
    w.title("Settings")
    w.configure(bg=CARD)
    w.geometry("520x390")
    w.resizable(False, False)
    w.transient(self.root)
    w.grab_set()

    tk.Label(w, text="Security settings", font=("Segoe UI", 17, "bold"),
             bg=CARD, fg=FG).pack(anchor="w", padx=24, pady=(22, 8))
    tk.Label(w, text="Choose how this app unlocks your accounts.",
             bg=CARD, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=24, pady=(0, 18))

    # The default is always to ask for the password unless a remembered
    # DPAPI credential exists because the user explicitly opted in.
    ask_every_time = tk.BooleanVar(value=not REMEMBER_FILE.exists())
    check = tk.Checkbutton(
        w, text="Ask for my password every time I open the app",
        variable=ask_every_time, command=lambda: update_warning(),
        bg=CARD, fg=FG, activebackground=CARD, activeforeground=FG,
        selectcolor=BG, font=("Segoe UI", 10, "bold"), wraplength=450,
        justify="left"
    )
    check.pack(anchor="w", padx=24, pady=(0, 10))

    warning = tk.Label(w, text="", bg=CARD, fg=MUTED, wraplength=455,
                       justify="left", font=("Segoe UI", 9))
    warning.pack(anchor="w", padx=28, pady=(0, 18))

    def update_warning():
        if ask_every_time.get():
            warning.config(
                text="ON (recommended): You must enter your master password each time. "
                     "This gives better protection if someone else opens your Windows account. "
                     "If you forget the password, the vault cannot be recovered.",
                fg="#9aabc2"
            )
        else:
            warning.config(
                text="OFF: This PC will remember the unlock password using Windows protection. "
                     "The app can open without asking next time. This is more convenient, but "
                     "malware or someone using your Windows account may be able to access your "
                     "accounts. Use this only on a trusted, password-protected PC.",
                fg="#ffcc80"
            )
    update_warning()

    def apply():
        if ask_every_time.get():
            try:
                if REMEMBER_FILE.exists():
                    REMEMBER_FILE.unlink()
                messagebox.showinfo(
                    "Settings saved",
                    "The app will ask for your master password every time you open it.",
                    parent=w
                )
                w.destroy()
            except Exception as exc:
                messagebox.showerror("Could not save setting", str(exc), parent=w)
            return

        # Verify the master password before saving it for this Windows user.
        pw = simpledialog.askstring(
            "Confirm master password",
            "Enter your master password to enable Remember on this PC:",
            show="•", parent=w
        )
        if pw is None:
            return
        try:
            # Confirm the password actually unlocks the current vault.
            decrypt_vault(json.loads(DATA.read_text(encoding="utf-8")), pw)
            save_remembered_password(pw)
            messagebox.showwarning(
                "Remember on this PC enabled",
                "Your password is now protected by Windows for this user account. "
                "Anyone or any malware running as your Windows user may still be able to "
                "access the app. Keep your Windows account protected.",
                parent=w
            )
            w.destroy()
        except Exception:
            messagebox.showerror(
                "Password not accepted",
                "That password did not unlock your vault, or Windows could not save it. "
                "Your current setting has not been changed.",
                parent=w
            )

    actions = tk.Frame(w, bg=CARD)
    actions.pack(fill="x", padx=24, pady=(4, 20))
    self.btn(actions, "Cancel", w.destroy).pack(side="right")
    self.btn(actions, "Save setting", apply, True).pack(side="right", padx=8)

 def setstatus(self,s): self.status.set(s)
 def save(self):
    try:
        path=DATA
        envelope=encrypt_vault({"app":"Authenticator Local Vault","version":2,"accounts":self.accounts}, self.master_password)
        temp_path=path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(envelope,indent=2),encoding="utf-8")
        temp_path.replace(path)
        self.data_path=DATA
        self.pathlabel.config(text=str(path)); self.setstatus(f"Encrypted vault saved · {len(self.accounts)} account(s)")
    except Exception as e: messagebox.showerror("Save failed",str(e))
 def load(self,silent=False,path=None):
    path=Path(path) if path else DATA
    if not path.exists():
        if not silent: messagebox.showinfo("File not found",str(path))
        return
    try:
        raw_obj=json.loads(path.read_text(encoding="utf-8"))
        if path == DATA:
            obj=decrypt_vault(raw_obj, self.master_password)
        else:
            # External JSON files are treated as explicit imports; they may be plaintext.
            obj=raw_obj
        items=obj.get("accounts",[]) if isinstance(obj,dict) else obj
        clean=[]
        for a in items:
            if not a.get("secret"): continue
            secret=a["secret"].replace(" ","").replace("-","").upper(); pyotp.TOTP(secret).now()
            clean.append({"issuer":a.get("issuer","Authenticator"),"name":a.get("name","Account"),"secret":secret,"digits":int(a.get("digits",6)),"period":int(a.get("period",30))})
        self.accounts=clean
        self.data_path=DATA
        self.pathlabel.config(text=str(DATA))
        self.render()
        if path == DATA:
            self.setstatus(f"Unlocked encrypted vault · {len(clean)} account(s)")
        else:
            if messagebox.askyesno("Import accounts", f"Import {len(clean)} accounts into your encrypted vault?"):
                self.save()
            else:
                self.accounts=[]
                self.render()
        if not silent: messagebox.showinfo("Loaded",f"Loaded {len(clean)} accounts.")
    except Exception as e: messagebox.showerror("Load failed",str(e))
 def load_other(self):
    p=filedialog.askopenfilename(filetypes=[("JSON/TXT","*.json *.txt"),("All files","*.*")])
    if p and messagebox.askyesno("Load file","Replace current accounts with this file?"): self.load(path=p)
 def open_folder(self):
    try: os.startfile(str(DATA.parent))
    except Exception: messagebox.showinfo("Folder",str(DATA.parent))
 def render(self):
    for w in self.list.winfo_children(): w.destroy()
    self.widgets={}; q=self.search.get().lower().strip()
    found=[(i,a) for i,a in enumerate(self.accounts) if q in (a.get("issuer","")+" "+a.get("name","")).lower()]
    if not found:
        f=tk.Frame(self.list,bg=CARD,highlightbackground=LINE,highlightthickness=1); f.pack(fill="both",expand=True)
        tk.Label(f,text="＋" if not self.accounts else "⌕",font=("Segoe UI",34),bg=CARD,fg=BLUE).pack(pady=(60,6))
        tk.Label(f,text="Your vault is empty" if not self.accounts else "No matching accounts",font=("Segoe UI",15,"bold"),bg=CARD,fg=FG).pack()
        tk.Label(f,text="Add an account or import QR screenshots from Google Authenticator.",bg=CARD,fg=MUTED).pack(pady=(8,60)); return
    cv=tk.Canvas(self.list,bg=BG,highlightthickness=0); sb=ttk.Scrollbar(self.list,orient="vertical",command=cv.yview)
    inner=tk.Frame(cv,bg=BG); win=cv.create_window((0,0),window=inner,anchor="nw")
    inner.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all"))); cv.bind("<Configure>",lambda e:cv.itemconfigure(win,width=e.width))
    cv.configure(yscrollcommand=sb.set); cv.pack(side="left",fill="both",expand=True); sb.pack(side="right",fill="y")
    for i,a in found:
        card=tk.Frame(inner,bg=CARD,highlightbackground=LINE,highlightthickness=1); card.pack(fill="x",pady=5)
        top=tk.Frame(card,bg=CARD); top.pack(fill="x",padx=15,pady=(11,0))
        tk.Label(top,text=(a.get("issuer") or "A")[0].upper(),bg=BLUE2,fg=BLUE,font=("Segoe UI",12,"bold"),width=3).pack(side="left",ipady=5,padx=(0,11))
        labels=tk.Frame(top,bg=CARD); labels.pack(side="left",fill="x",expand=True)
        tk.Label(labels,text=a.get("issuer","Authenticator"),bg=CARD,fg=FG,font=("Segoe UI",11,"bold")).pack(anchor="w")
        tk.Label(labels,text=a.get("name","Account"),bg=CARD,fg=MUTED,font=("Segoe UI",9)).pack(anchor="w")
        self.btn(top,"Edit",lambda i=i:self.edit(i)).pack(side="right",padx=(5,0)); self.btn(top,"Delete",lambda i=i:self.delete(i)).pack(side="right")
        row=tk.Frame(card,bg=CARD); row.pack(fill="x",padx=18,pady=(7,0))
        code=tk.Label(row,text="------",bg=CARD,fg=FG,font=("Consolas",25,"bold")); code.pack(side="left")
        self.btn(row,"Copy code",lambda i=i:self.copy(i)).pack(side="right",pady=2)
        tr=tk.Frame(card,bg=CARD); tr.pack(fill="x",padx=18,pady=(0,11))
        timer=tk.Label(tr,text="Refreshes in 30s",bg=CARD,fg=MUTED,font=("Segoe UI",9)); timer.pack(side="left")
        bar=tk.Canvas(tr,height=4,bg=CARD2,highlightthickness=0); bar.pack(side="right",fill="x",expand=True,padx=(25,0))
        self.widgets[i]=(code,timer,bar)
 def tick(self):
    now=int(time.time())
    for i,(code,timer,bar) in list(self.widgets.items()):
        if i>=len(self.accounts): continue
        a=self.accounts[i]; period=int(a.get("period",30))
        try:
            val=pyotp.TOTP(a["secret"],digits=int(a.get("digits",6)),interval=period).now()
            code.config(text=(val[:3]+" "+val[3:] if len(val)==6 else val),fg=FG)
            remain=period-now%period; timer.config(text=f"Refreshes in {remain}s")
            bar.delete("all"); width=max(bar.winfo_width(),100); bar.create_rectangle(0,0,width*remain/period,5,fill=BLUE,outline="")
        except Exception: code.config(text="INVALID",fg=RED)
    self.root.after(250,self.tick)
 def add(self): self.dialog()
 def edit(self,i): self.dialog(i)
 def dialog(self,i=None):
    old=self.accounts[i] if i is not None else {}
    w=tk.Toplevel(self.root); w.title("Edit account" if i is not None else "Add account"); w.configure(bg=CARD); w.geometry("440x390"); w.resizable(False,False); w.transient(self.root); w.grab_set()
    tk.Label(w,text="Edit account" if i is not None else "Add account",font=("Segoe UI",17,"bold"),bg=CARD,fg=FG).pack(anchor="w",padx=24,pady=(20,12))
    fields={}
    for key,label in [("issuer","Service / issuer"),("name","Account / email"),("secret","Base32 secret key")]:
        tk.Label(w,text=label,bg=CARD,fg=MUTED,font=("Segoe UI",9,"bold")).pack(anchor="w",padx=24,pady=(7,3))
        e=tk.Entry(w,bg=BG,fg=FG,insertbackground=FG,relief="flat",font=("Segoe UI",10)); e.pack(fill="x",padx=24,ipady=8); e.insert(0,old.get(key,"")); fields[key]=e
    row=tk.Frame(w,bg=CARD); row.pack(fill="x",padx=24,pady=12)
    tk.Label(row,text="Digits",bg=CARD,fg=MUTED).pack(side="left"); digits=ttk.Combobox(row,values=("6","8"),width=5,state="readonly"); digits.set(str(old.get("digits",6))); digits.pack(side="left",padx=8)
    tk.Label(row,text="Period",bg=CARD,fg=MUTED).pack(side="left",padx=(12,0)); period=ttk.Combobox(row,values=("30","60"),width=5,state="readonly"); period.set(str(old.get("period",30))); period.pack(side="left",padx=8)
    def submit():
        a={"issuer":fields["issuer"].get().strip() or "Authenticator","name":fields["name"].get().strip() or "Account","secret":fields["secret"].get().strip().replace(" ","").replace("-","").upper(),"digits":int(digits.get()),"period":int(period.get())}
        try: pyotp.TOTP(a["secret"],digits=a["digits"],interval=a["period"]).now()
        except Exception as e: messagebox.showerror("Invalid secret",f"Check the Base32 secret.\n{e}",parent=w); return
        if i is None:self.accounts.append(a)
        else:self.accounts[i]=a
        self.save(); self.render(); w.destroy()
    actions=tk.Frame(w,bg=CARD); actions.pack(fill="x",padx=24,pady=5)
    self.btn(actions,"Cancel",w.destroy).pack(side="right"); self.btn(actions,"Save account",submit,True).pack(side="right",padx=8)
 def delete(self,i):
    a=self.accounts[i]
    if messagebox.askyesno("Delete account",f"Delete {a.get('issuer')} — {a.get('name')}?"):
        self.accounts.pop(i); self.save(); self.render()
 def copy(self,i):
    a=self.accounts[i]; code=pyotp.TOTP(a["secret"],digits=int(a.get("digits",6)),interval=int(a.get("period",30))).now()
    self.root.clipboard_clear(); self.root.clipboard_append(code); self.setstatus(f"Copied code for {a.get('issuer')}")
 def import_qr(self):
    paths=filedialog.askopenfilenames(title="Select one or more QR screenshots",filetypes=[("Images","*.png *.jpg *.jpeg *.bmp *.webp"),("All files","*.*")])
    if not paths:return
    found=[]; errors=[]
    for p in paths:
        try:
            for text in decode_image(p): found.extend(parse_qr(text))
        except Exception as e: errors.append(Path(p).name+": "+str(e))
    existing={(a["secret"],a.get("issuer"),a.get("name")) for a in self.accounts}; added=0
    for a in found:
        key=(a["secret"],a.get("issuer"),a.get("name"))
        if a["secret"] and key not in existing:self.accounts.append(a);existing.add(key);added+=1
    if added:self.save();self.render()
    msg=f"Added {added} new account(s)."
    if not found:msg+="\nNo supported QR codes were decoded."
    if errors:msg+="\n\nSome images could not be read:\n"+"\n".join(errors[:5])
    messagebox.showinfo("QR import",msg)
 def export_qr(self):
    if not self.accounts: messagebox.showinfo("Export QR","No accounts to export.");return
    folder=filedialog.askdirectory(title="Choose folder for QR export images")
    if not folder:return
    chunks=[self.accounts[i:i+5] for i in range(0,len(self.accounts),5)]
    try:
        for i,chunk in enumerate(chunks):
            uri=migration_uri(chunk,i,len(chunks)); qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L,box_size=8,border=3); qr.add_data(uri);qr.make(fit=True)
            qr.make_image(fill_color="black",back_color="white").save(Path(folder)/f"authenticator-export-{i+1}-of-{len(chunks)}.png")
        self.setstatus(f"Exported {len(self.accounts)} account(s) into {len(chunks)} QR image(s)")
        messagebox.showinfo("Export complete",f"Saved {len(chunks)} QR image(s) to:\n{folder}\n\nTreat these images like passwords.")
    except Exception as e:messagebox.showerror("Export failed",str(e))
 def close(self):
    self.save();self.root.destroy()

if __name__=="__main__":
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        password = get_remembered_password()
        if password is not None and DATA.exists():
            try:
                decrypt_vault(json.loads(DATA.read_text(encoding="utf-8")), password)
            except Exception:
                password = None
                try:
                    REMEMBER_FILE.unlink(missing_ok=True)
                except Exception:
                    pass
        if password is None:
            password = password_prompt(root, DATA.exists())
        if password is None:
            root.destroy()
            sys.exit(0)
        root.deiconify()
        app = App(root, password)
        root.mainloop()
    except Exception as exc:
        import traceback
        details = traceback.format_exc()
        try:
            log_path = BASE / "startup-error.txt"
            log_path.write_text(details, encoding="utf-8")
        except Exception:
            log_path = None
        try:
            if root is None:
                root = tk.Tk()
                root.withdraw()
            messagebox.showerror(
                "Authenticator startup error",
                f"{exc}\\n\\nFull details saved to: {log_path or 'could not write log'}"
            )
        except Exception:
            pass
        raise
