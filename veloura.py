"""
VELOURA - single-file FastAPI shop
Install: pip install fastapi uvicorn sqlalchemy python-multipart
Run:     uvicorn veloura:app --reload
Open:    http://127.0.0.1:8000

Contains the complete website, FastAPI APIRouter, two SQLAlchemy models,
registration/login, salted hashlib password hashing, and product add/list/delete.
"""
import hashlib, hmac, secrets
from fastapi import APIRouter, FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Integer, String, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

engine = create_engine("sqlite:///./veloura.db", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase): pass

# MODEL 1
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))

# MODEL 2
class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    price: Mapped[float] = mapped_column(Float)
    description: Mapped[str] = mapped_column(String(500))

Base.metadata.create_all(engine)

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return salt + "$" + hashed.hex()

def verify_password(password, saved):
    try:
        salt, old_hash = saved.split("$", 1)
        new_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
        return hmac.compare_digest(new_hash, old_hash)
    except ValueError:
        return False

app = FastAPI(title="VELOURA")
router = APIRouter()

STYLE = """
*{box-sizing:border-box}body{margin:0;background:#faf7f2;color:#29231f;font-family:Arial,sans-serif}
header{padding:22px 7%;background:white;border-bottom:1px solid #e9e1d8;display:flex;justify-content:space-between;align-items:center}
.brand{font: bold 28px Georgia;letter-spacing:5px}.wrap{max-width:1000px;margin:50px auto;padding:0 20px}
.panel,.product{background:white;border:1px solid #e9e1d8;border-radius:16px;padding:26px}
.panel{max-width:540px;margin:auto}h1,h2,h3{font-family:Georgia;font-weight:normal}h1{font-size:40px}
p{color:#77716a;line-height:1.5}label{display:block;margin-top:12px}
input,textarea{width:100%;padding:13px;margin:7px 0 14px;border:1px solid #e9e1d8;border-radius:8px;font:inherit}
textarea{min-height:80px}.btn{background:#29231f;color:white;border:0;border-radius:8px;padding:13px 20px;cursor:pointer}
.alt{background:#b77c72}.tabs{display:flex;gap:10px;margin:22px 0}.tabs button{padding:10px 16px;border:1px solid #ddd;background:white;border-radius:20px;cursor:pointer}
.active{background:#29231f!important;color:white}.hidden{display:none}.notice{padding:12px;background:#f5eee8;border-radius:8px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;margin:25px 0}
.price{font-size:20px;color:#b77c72;font-weight:bold}.link{border:0;background:none;color:#b77c72;text-decoration:underline;cursor:pointer}
.small{font-size:12px;color:#888}@media(max-width:600px){h1{font-size:32px}header{padding:18px}}
"""

LOGIN = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VELOURA</title><style>""" + STYLE + """</style></head><body>
<header><div class="brand">VELOURA</div><small>CURATED FINDS · EVERYDAY ELEGANCE</small></header>
<main class="wrap"><section class="panel"><center><p>WELCOME TO VELOURA</p><h1>Find your everyday something special.</h1><p>A simple online shop for thoughtful finds.</p></center>
<div class="tabs"><button id="lt" class="active" onclick="toggle('login')">Log in</button><button id="rt" onclick="toggle('register')">Register</button></div>
<div id="msg" class="notice hidden"></div>
<form id="login"><label>Username</label><input name="username" required><label>Password</label><input name="password" type="password" required><button class="btn" style="width:100%">Log in</button></form>
<form id="register" class="hidden"><label>Username</label><input name="username" minlength="3" required><label>Password</label><input name="password" type="password" minlength="6" required><button class="btn alt" style="width:100%">Create account</button></form>
<p class="small" style="text-align:center">Passwords are stored as salted hashes.</p></section></main>
<script>
const msg=document.getElementById('msg');
function toggle(v){login.classList.toggle('hidden',v!=='login');register.classList.toggle('hidden',v!=='register');lt.classList.toggle('active',v==='login');rt.classList.toggle('active',v==='register');msg.classList.add('hidden')}
async function post(form,url){let r=await fetch(url,{method:'POST',body:new FormData(form)}),d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
register.addEventListener('submit',async e=>{e.preventDefault();try{let d=await post(e.target,'/register');toggle('login');msg.textContent=d.message;msg.classList.remove('hidden');e.target.reset()}catch(x){msg.textContent=x.message;msg.classList.remove('hidden')}});
login.addEventListener('submit',async e=>{e.preventDefault();try{let d=await post(e.target,'/login');localStorage.setItem('velouraUser',d.username);location.href='/main'}catch(x){msg.textContent=x.message;msg.classList.remove('hidden')}});
</script></body></html>"""

MAIN = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VELOURA Shop</title><style>""" + STYLE + """</style></head><body>
<header><div><div class="brand">VELOURA</div><small>THE LITTLE THINGS, BEAUTIFULLY FOUND</small></div><span id="welcome"></span><button class="link" onclick="localStorage.removeItem('velouraUser');location.href='/'">Log out</button></header>
<main class="wrap"><p>THE VELOURA COLLECTION</p><h1>Discover your next favorite.</h1><p>Explore the collection or add a product to your shop.</p>
<section id="products" class="grid"></section><section class="panel" style="max-width:none"><h2>Add a product</h2><form id="add"><label>Product name</label><input name="name" required placeholder="Product name"><label>Price (PHP)</label><input name="price" type="number" min="0" step=".01" required placeholder="Price"><label>Description</label><textarea name="description" required placeholder="Product description"></textarea><button class="btn alt">＋ Add Product</button></form><div id="notice" class="notice hidden"></div></section></main>
<script>
if(!localStorage.getItem('velouraUser'))location.href='/';
document.getElementById('welcome').textContent='Hello, '+(localStorage.getItem('velouraUser')||'');
function safe(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function load(){let items=await (await fetch('/api/products')).json();products.innerHTML=items.length?items.map(p=>`<article class="product"><p class="small">VELOURA FIND</p><h3>${safe(p.name)}</h3><div class="price">₱${Number(p.price).toFixed(2)}</div><p>${safe(p.description)}</p><button class="link" onclick="removeItem(${p.id})">Remove</button></article>`).join(''):'<div class="panel"><h2>Your collection starts here.</h2><p>Add your first product below.</p></div>'}
async function removeItem(id){if(confirm('Remove this product?')){await fetch('/api/products/'+id,{method:'DELETE'});load()}}
add.addEventListener('submit',async e=>{e.preventDefault();let r=await fetch('/api/products',{method:'POST',body:new FormData(e.target)}),d=await r.json();notice.textContent=r.ok?d.message:(d.detail||'Could not add product');notice.classList.remove('hidden');if(r.ok){e.target.reset();load()}});
load();
</script></body></html>"""

@router.get("/", response_class=HTMLResponse)
def home(): return HTMLResponse(LOGIN)

@router.get("/main", response_class=HTMLResponse)
def main_page(): return HTMLResponse(MAIN)

@router.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    db = Session()
    try:
        username = username.strip()
        if len(username) < 3 or len(password) < 6:
            raise HTTPException(400, "Username needs 3+ characters and password 6+.")
        if db.query(User).filter_by(username=username).first():
            raise HTTPException(400, "Username already exists.")
        db.add(User(username=username, password_hash=hash_password(password)))
        db.commit()
        return {"message": "Account created. You can now log in."}
    finally: db.close()

@router.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = Session()
    try:
        user = db.query(User).filter_by(username=username.strip()).first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(401, "Incorrect username or password.")
        return {"message": "Login successful", "username": user.username}
    finally: db.close()

@router.get("/api/products")
def list_products():
    db = Session()
    try:
        return [{"id":p.id,"name":p.name,"price":p.price,"description":p.description}
                for p in db.query(Product).order_by(Product.id.desc()).all()]
    finally: db.close()

@router.post("/api/products")
def add_product(name: str = Form(...), price: float = Form(...), description: str = Form(...)):
    db = Session()
    try:
        if not name.strip() or price < 0: raise HTTPException(400, "Enter a valid name and price.")
        p = Product(name=name.strip(), price=price, description=description.strip())
        db.add(p); db.commit(); db.refresh(p)
        return {"message":"Product added successfully","id":p.id}
    finally: db.close()

@router.delete("/api/products/{product_id}")
def delete_product(product_id: int):
    db = Session()
    try:
        p = db.query(Product).filter_by(id=product_id).first()
        if not p: raise HTTPException(404, "Product not found.")
        db.delete(p); db.commit()
        return {"message":"Product deleted"}
    finally: db.close()

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("veloura:app", host="127.0.0.1", port=8000, reload=True)
