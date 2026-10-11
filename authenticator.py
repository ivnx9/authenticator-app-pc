import sys, subprocess, importlib.util, json, time, base64, urllib.parse, os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


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

for mod, pkg in [("pyotp", "pyotp"), ("qrcode", "qrcode[pil]"), ("cv2", "opencv-python"), ("PIL", "Pillow")]:
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

# Persistent storage outside the PyInstaller temporary extraction folder.
# On Windows this resolves to %LOCALAPPDATA%\Authenticator.
if os.name == "nt":
    _appdata = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    BASE = Path(_appdata) / "Authenticator"
else:
    BASE = Path.home() / ".local" / "share" / "Authenticator"
BASE.mkdir(parents=True, exist_ok=True)
DATA = BASE / "authenticator-data.json"
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
 def __init__(self,root):
    self.root=root
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
    self.accounts=[]; self.widgets={}; self.search=tk.StringVar(); self.status=tk.StringVar(value="Ready · Auto-saves to authenticator-data.json")
    st=ttk.Style(); st.theme_use("clam"); st.configure("Treeview",background=CARD,foreground=FG,fieldbackground=CARD,rowheight=36)
    head=tk.Frame(root,bg=BG); head.pack(fill="x",padx=24,pady=(22,15))
    tk.Label(head,text="◈",font=("Segoe UI",30,"bold"),bg=BG,fg=BLUE).pack(side="left",padx=(0,12))
    title=tk.Frame(head,bg=BG); title.pack(side="left",expand=True,fill="x")
    tk.Label(title,text="Authenticator",font=("Segoe UI",22,"bold"),bg=BG,fg=FG).pack(anchor="w")
    tk.Label(title,text="Offline codes · Private local JSON storage",font=("Segoe UI",9),bg=BG,fg=MUTED).pack(anchor="w")
    self.btn(head,"＋ Add",self.add,True).pack(side="left",padx=3)
    self.btn(head,"Import QR",self.import_qr).pack(side="left",padx=3)
    self.btn(head,"Export QR",self.export_qr).pack(side="left",padx=3)
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
 def setstatus(self,s): self.status.set(s)
 def save(self):
    try:
        path=getattr(self,"data_path",DATA); path.write_text(json.dumps({"app":"Authenticator Local Vault","version":1,"accounts":self.accounts},indent=2),encoding="utf-8")
        self.pathlabel.config(text=str(path)); self.setstatus(f"Saved {len(self.accounts)} account(s) · {path.name}")
    except Exception as e: messagebox.showerror("Save failed",str(e))
 def load(self,silent=False,path=None):
    path=Path(path) if path else DATA
    if not path.exists():
        if not silent: messagebox.showinfo("File not found",str(path))
        return
    try:
        obj=json.loads(path.read_text(encoding="utf-8")); items=obj.get("accounts",[]) if isinstance(obj,dict) else obj
        clean=[]
        for a in items:
            if not a.get("secret"): continue
            secret=a["secret"].replace(" ","").replace("-","").upper(); pyotp.TOTP(secret).now()
            clean.append({"issuer":a.get("issuer","Authenticator"),"name":a.get("name","Account"),"secret":secret,"digits":int(a.get("digits",6)),"period":int(a.get("period",30))})
        self.accounts=clean; self.data_path=path; self.pathlabel.config(text=str(path)); self.render(); self.setstatus(f"Loaded {len(clean)} account(s)")
        if not silent: messagebox.showinfo("Loaded",f"Loaded {len(clean)} accounts")
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
    root=tk.Tk(); app=App(root); root.mainloop()
