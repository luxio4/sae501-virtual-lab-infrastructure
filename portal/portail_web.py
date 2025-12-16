import time
import mysql.connector
import base64
import re
import unicodedata

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException

# ============================================================================#
# CONFIG
# ============================================================================#

app = Flask(__name__)
app.secret_key = "progtr00"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Proxmox
PROXMOX_HOST = "192.168.1.201"
PROXMOX_NODE = "pve"
PROXMOX_PORT = 8006

# MySQL Guacamole
MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = 3306
MYSQL_DB = "guacamole_db"
MYSQL_USER = "guacamole_user"
MYSQL_PASSWORD = "imbbieYKdFWfd"

# Compte partagé SAE dans Guacamole (doit exister dans guacamole_entity.name)
GUAC_SAE_USERNAME = "SAE"

# URL de base (contient déjà le chemin vers le client)
GUAC_BASE_URL = "https://88.121.251.128:33501/guacamole/#/client"

# Stockage en mémoire des sessions Proxmox par utilisateur
connected_users = {}


# ============================================================================#
# MODEL UTILISATEUR
# ============================================================================#


class User(UserMixin):
    def __init__(self, id, proxmox, rdp_username, rdp_password, guac_username):
        """
        id            : identifiant de connexion Proxmox (ex : user@picamal.rt)
        proxmox       : instance ProxmoxAPI connectée
        rdp_username  : login utilisé pour la session RDP (ex : rleroy)
        rdp_password  : mot de passe RDP (identique au mot de passe saisi au login)
        guac_username : login utilisé dans Guacamole (guacamole_entity.name),
                        ex : mduda@picamal.rt
        """
        self.id = id
        self.proxmox = proxmox
        self.rdp_username = rdp_username
        self.rdp_password = rdp_password
        self.guac_username = guac_username


@login_manager.user_loader
def load_user(user_id):
    return connected_users.get(user_id)


# ============================================================================#
# HELPERS GLOBAUX
# ============================================================================#


def get_proxmox():
    if not current_user.is_authenticated:
        raise RuntimeError("User non authentifié")
    return current_user.proxmox


def sanitize_username_base(username: str) -> str:
    """
    Base du nom de VM et du pool à partir du username.
    Garde uniquement [a-zA-Z0-9-].
    Ex : "adam@pve" -> "adam-pve"
    """
    base = re.sub(r"[^a-zA-Z0-9\-]", "-", username)
    base = base.strip("-")
    if not base:
        base = "user"
    return base


def normalize_ascii(s: str) -> str:
    """
    Supprime les accents pour avoir un login simple : é -> e, ç -> c, etc.
    """
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def compute_proxmox_username(username: str) -> str:
    """
    Normalise le login Proxmox pour utiliser toujours le realm LDAP 'picamal.rt'.

    Exemples :
      - "mduda"            -> "mduda@picamal.rt"
      - "mduda@pve"        -> "mduda@picamal.rt"
      - "PICA\\mduda"      -> "mduda@picamal.rt"
      - "mduda@picamal.rt" -> "mduda@picamal.rt"
    """
    base = username.strip()

    # Si style domaine Windows : PICA\mduda
    if "\\" in base:
        base = base.split("\\", 1)[-1].strip()

    # Si style user@realm
    if "@" in base:
        local, _realm = base.split("@", 1)
        local = local.strip()
        return f"{local}@picamal.rt"

    # Sinon, simple login -> on ajoute le realm LDAP
    return f"{base}@picamal.rt"


def compute_rdp_username_from_login(username: str) -> str:
    """
    Construit un login RDP sous la forme :
        première lettre du prénom + nom
    à partir du login de connexion.
    """
    base = username

    # Enlever le domaine s'il est présent (user@domaine)
    if "@" in base:
        base = base.split("@", 1)[0]

    # Enlever le domaine NetBIOS si présent (PICA\user)
    if "\\" in base:
        base = base.split("\\", 1)[-1]

    base = base.strip()
    fallback = base.lower()

    # On essaie de séparer prénom / nom avec ., -, _, espace
    tokens = re.split(r"[.\-_ ]+", base)
    tokens = [t for t in tokens if t]

    if len(tokens) >= 2:
        first = tokens[0]
        last = tokens[-1]
        first = normalize_ascii(first).lower()
        last = normalize_ascii(last).lower()
        if first and last:
            return first[0] + last  # première lettre du prénom + nom

    # Sinon, on essaie : première lettre + reste
    base_ascii = normalize_ascii(base).lower()
    if len(base_ascii) > 1:
        return base_ascii[0] + base_ascii[1:]

    # En dernier recours, fallback
    return fallback


def compute_guac_username_from_login(username: str) -> str:
    """
    Construit le login Guacamole (guacamole_entity.name),
    typiquement au format : mduda@picamal.rt
    à partir de ce que l'utilisateur a tapé.
    """
    base = username.strip()

    # Si style user@domaine
    if "@" in base:
        local, domain = base.split("@", 1)
        local = local.strip()
        domain = domain.strip().lower()
        if domain == "picamal.rt":
            return f"{local}@{domain}"
        else:
            # Si user@pve ou user@pam, on force vers picamal.rt
            return f"{local}@picamal.rt"

    # Si style PICA\user
    if "\\" in base:
        local = base.split("\\", 1)[-1].strip()
        return f"{local}@picamal.rt"

    # Sinon, login simple -> login@picamal.rt
    return f"{base}@picamal.rt"


def add_vm_to_pool_if_exists(username: str, vmid: int):
    """
    Si un pool portant le nom sanitize_username_base(username) existe,
    ajoute la VM au pool.
    """
    proxmox = get_proxmox()
    poolid = sanitize_username_base(username)

    try:
        proxmox.pools(poolid).get()  # vérifie l'existence
        proxmox.pools(poolid).put(vms=vmid)
        print(f"[INFO] VM {vmid} ajoutée au pool {poolid}.")
    except ResourceException as e:
        print(f"[WARN] Pool {poolid} introuvable ou inaccessible : {e}")
    except Exception as e:
        print(f"[WARN] Impossible d'ajouter VM {vmid} au pool {poolid} : {e}")


# ============================================================================#
# ROUTES AUTH
# ============================================================================#


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        raw_username = request.form["username"]  # ce que tape l'utilisateur
        password = request.form["password"]

        # Normalisation pour avoir le bon user Proxmox (avec le realm picamal.rt)
        proxmox_username = compute_proxmox_username(raw_username)

        try:
            proxmox = ProxmoxAPI(
                PROXMOX_HOST,
                user=proxmox_username,
                password=password,
                verify_ssl=False,
                port=PROXMOX_PORT,
            )

            # Tester la connexion avec une requête simple
            proxmox.nodes.get()

            # Login RDP : basé sur ce que l'utilisateur a tapé
            rdp_username = compute_rdp_username_from_login(raw_username)
            rdp_password = password

            # Login Guacamole : ex mduda@picamal.rt
            guac_username = compute_guac_username_from_login(raw_username)

            user = User(proxmox_username, proxmox, rdp_username, rdp_password, guac_username)
            connected_users[proxmox_username] = user
            login_user(user)

            flash(
                f"Connexion Proxmox réussie. "
                f"RDP = {rdp_username}, Guacamole = {guac_username}"
            )
            return redirect(url_for("dashboard"))

        except ResourceException as e:
            flash(f"Échec connexion Proxmox : {str(e)}")
        except Exception as e:
            flash(f"Erreur inattendue : {str(e)}")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    if user_id in connected_users:
        del connected_users[user_id]
    flash("Déconnecté")
    return redirect(url_for("login"))


# ============================================================================#
# MYSQL / GUACAMOLE
# ============================================================================#


def db():
    return mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
    )


def get_entity_id(username):
    cnx = db()
    cur = cnx.cursor()
    cur.execute(
        "SELECT entity_id FROM guacamole_entity WHERE name=%s AND type='USER'",
        (username,),
    )
    r = cur.fetchone()
    cur.close()
    cnx.close()
    return r[0] if r else None


def get_or_create_entity_and_user_id(username):
    """
    Pour un user LDAP (ex: mduda@picamal.rt), crée :
      - l'entry dans guacamole_entity si absente
      - l'entry associée dans guacamole_user si absente
    et renvoie entity_id.
    """
    cnx = db()
    cur = cnx.cursor()

    # 1) entity dans guacamole_entity
    cur.execute(
        "SELECT entity_id FROM guacamole_entity WHERE name=%s AND type='USER'",
        (username,),
    )
    r = cur.fetchone()
    if r:
        eid = r[0]
    else:
        cur.execute(
            "INSERT INTO guacamole_entity (name, type) VALUES (%s, 'USER')",
            (username,),
        )
        eid = cur.lastrowid

    # 2) user dans guacamole_user associé à cet entity_id
    cur.execute(
        "SELECT user_id FROM guacamole_user WHERE entity_id=%s",
        (eid,),
    )
    r2 = cur.fetchone()
    if not r2:
        # On crée un user MySQL "virtuel" avec un mot de passe bidon,
        # l'auth continue à passer par LDAP.
        cur.execute(
            """
            INSERT INTO guacamole_user (
              entity_id,
              password_hash,
              password_salt,
              password_date,
              disabled,
              expired,
              access_window_start,
              access_window_end,
              valid_from,
              valid_until,
              timezone,
              full_name,
              email_address,
              organization,
              organizational_role
            ) VALUES (
              %s,
              UNHEX(SHA2('dummy',256)),
              NULL,
              NOW(),
              0,
              0,
              NULL,
              NULL,
              NULL,
              NULL,
              NULL,
              NULL,
              NULL,
              NULL,
              NULL
            )
            """,
            (eid,),
        )

    cnx.commit()
    cur.close()
    cnx.close()
    return eid


def get_sae_entity_id():
    return get_entity_id(GUAC_SAE_USERNAME)


def create_guac_connection(guac_username, vmid, ip, rdp_username, rdp_password):
    """
    Crée une connexion RDP dans Guacamole et donne les droits.
    Utilise :
      - guac_username : nom du user dans Guacamole (ex: mduda@picamal.rt)
      - rdp_username / rdp_password : pour la session RDP Windows
    """
    cnx = db()
    cur = cnx.cursor()

    guac_user = guac_username
    conn_name = f"{guac_user}-vm-{vmid}"

    print(f"[DEBUG] create_guac_connection: guac_user={guac_user}, vmid={vmid}, ip={ip}, rdp={rdp_username}")

    # Création de la connexion
    cur.execute(
        "INSERT INTO guacamole_connection (connection_name, protocol) "
        "VALUES (%s,'rdp')",
        (conn_name,),
    )
    connection_id = cur.lastrowid

    # Paramètres RDP
    params = {
        "hostname": ip,
        "port": "3389",
        "username": rdp_username,
        "password": rdp_password,
        "security": "any",
        "ignore-cert": "true",
    }

    for k, v in params.items():
        cur.execute(
            "INSERT INTO guacamole_connection_parameter "
            "(connection_id, parameter_name, parameter_value) "
            "VALUES (%s,%s,%s)",
            (connection_id, k, v),
        )

    # Droits
    uid = get_or_create_entity_and_user_id(guac_user)
    print(f"[DEBUG] entity_id for {guac_user} = {uid}")
    sae_id = get_sae_entity_id()

    for eid in [uid, sae_id]:
        if eid is None:
            continue
        for perm in ["READ", "UPDATE", "DELETE", "ADMINISTER"]:
            cur.execute(
                "INSERT INTO guacamole_connection_permission "
                "(entity_id, connection_id, permission) "
                "VALUES (%s,%s,%s)",
                (eid, connection_id, perm),
            )

    cnx.commit()
    cur.close()
    cnx.close()
    print(f"[DEBUG] created connection_id={connection_id} for {guac_user}")
    return connection_id


def delete_guac_connection(cid):
    cnx = db()
    cur = cnx.cursor()
    cur.execute(
        "DELETE FROM guacamole_connection_parameter WHERE connection_id=%s",
        (cid,),
    )
    cur.execute(
        "DELETE FROM guacamole_connection_permission WHERE connection_id=%s",
        (cid,),
    )
    cur.execute(
        "DELETE FROM guacamole_connection WHERE connection_id=%s",
        (cid,),
    )
    cnx.commit()
    cur.close()
    cnx.close()


def get_guac_connection_ids_for_vm(guac_username, vmid):
    """
    Retourne les connection_id Guacamole pour une VM donnée.
    On matche sur connection_name = "<guac_username>-vm-<vmid>".
    """
    conn_name = f"{guac_username}-vm-{vmid}"
    cnx = db()
    cur = cnx.cursor()
    cur.execute(
        "SELECT connection_id FROM guacamole_connection WHERE connection_name=%s",
        (conn_name,),
    )
    ids = [row[0] for row in cur.fetchall()]
    cur.close()
    cnx.close()
    return ids


def generate_guac_url(connection_id):
    """
    Génère l'URL complète pour accéder au client Guacamole.
    Format attendu par Guacamole : base64( ID + '\0' + TYPE + '\0' + SOURCE )
    """
    if not connection_id:
        return None

    raw_id = f"{connection_id}\0c\0mysql"
    token = base64.b64encode(raw_id.encode("utf-8")).decode("utf-8")
    base_url = GUAC_BASE_URL.rstrip("/")
    return f"{base_url}/{token}"


# ============================================================================#
# PROXMOX HELPERS
# ============================================================================#


def get_vm_ip(vmid, timeout=None):
    """
    Récupère l'IP de la VM via qemu-guest-agent.

    - Si timeout est None  -> boucle infinie jusqu'à ce qu'une IP soit trouvée.
    - Si timeout est un nombre de secondes -> on arrête et renvoie None à l'expiration.
    """
    proxmox = get_proxmox()
    deadline = None
    if timeout is not None:
        deadline = time.time() + timeout

    while True:
        if deadline is not None and time.time() > deadline:
            print(f"[WARN] Timeout expiré pour la VM {vmid}, aucune IP trouvée.")
            return None

        try:
            j = proxmox.nodes(PROXMOX_NODE).qemu(vmid).agent(
                "network-get-interfaces"
            ).get()
            data = j.get("data", j)
        except Exception as e:
            print(f"[WARN] Erreur qemu-guest-agent pour VM {vmid} : {e}")
            data = []

        interfaces = []
        if isinstance(data, list):
            interfaces = data
        elif isinstance(data, dict):
            if "result" in data and isinstance(data["result"], list):
                interfaces = data["result"]
            elif "interfaces" in data and isinstance(data["interfaces"], list):
                interfaces = data["interfaces"]
            else:
                interfaces = [data]

        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            ip_list = iface.get("ip-addresses", [])
            if not isinstance(ip_list, list):
                continue

            for ip in ip_list:
                if not isinstance(ip, dict):
                    continue
                addr = ip.get("ip-address")
                if (
                    addr
                    and ip.get("ip-address-type") == "ipv4"
                    and not addr.startswith("127.")
                ):
                    print(f"[INFO] IP détectée VM {vmid}: {addr}")
                    return addr

        print(f"[WAIT] IP pas encore prête pour VM {vmid}...")
        time.sleep(2)


def get_user_vms(username):
    """
    Récupère les VMs de l'utilisateur (côté Proxmox)
    et construit l'URL Guacamole correcte si une connexion existe.
    """
    proxmox = get_proxmox()
    base = sanitize_username_base(username)
    guac_user = current_user.guac_username
    vms_by_id = {}

    # 1) VMs du node filtrées par nom
    try:
        vms_all = proxmox.nodes(PROXMOX_NODE).qemu.get()
    except Exception as e:
        print(f"[ERROR] Impossible de récupérer les VMs : {e}")
        vms_all = []

    for vm in vms_all:
        name = vm.get("name", "")
        vmid = vm.get("vmid")
        if not name or vmid is None:
            continue
        if str(name).startswith(base + "-vm-") or str(name).startswith(base + "-pool-vm-"):
            vms_by_id[int(vmid)] = name

    # 2) VMs du pool
    poolid = base
    try:
        pool = proxmox.pools(poolid).get()
        members = pool.get("members", [])
        for m in members:
            mid = m.get("vmid")
            if mid is None and "id" in m:
                parts = str(m["id"]).split("/")
                try:
                    mid = int(parts[-1])
                except Exception:
                    mid = None
            if mid is None:
                continue
            mid = int(mid)
            if mid not in vms_by_id:
                vms_by_id[mid] = f"{base}-pool-vm-{mid}"
    except ResourceException:
        pass
    except Exception as e:
        print(f"[WARN] Impossible de lire le pool {poolid} : {e}")

    # 3) Construction de la liste finale avec URL Guacamole
    user_vms = []
    for vmid, name in vms_by_id.items():
        guac_url = None
        try:
            cids = get_guac_connection_ids_for_vm(guac_user, vmid)
            if cids:
                guac_url = generate_guac_url(cids[0])
        except Exception as e:
            print(
                f"[WARN] Impossible de récupérer la connexion Guac pour VM {vmid} : {e}"
            )

        user_vms.append({"vmid": vmid, "name": name, "guac_url": guac_url})

    user_vms.sort(key=lambda v: v["vmid"])
    return user_vms


# ============================================================================#
# DASHBOARD
# ============================================================================#


@app.route("/dashboard")
@login_required
def dashboard():
    username = current_user.id  # login Proxmox normalisé
    vms = get_user_vms(username)
    return render_template("dashboard.html", vms=vms)


# ============================================================================#
# ACTIONS SUR LES VMs
# ============================================================================#


@app.route("/start_vm/<int:vmid>")
@login_required
def start_vm(vmid):
    """
    - Démarre la VM
    - Crée (ou assure) la connexion Guacamole pour cette VM
    """
    proxmox = get_proxmox()
    username = current_user.id
    guac_user = current_user.guac_username

    print(f"[DEBUG] start_vm called by proxmox_user={username}, guac_user={guac_user}, vmid={vmid}")

    try:
        # Tentative de démarrage
        try:
            proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.start.post()
            flash(f"VM {vmid} démarrée avec succès")
        except ResourceException as e:
            if "already running" not in str(e):
                raise e

        guac_url = None
        try:
            # On regarde s'il existe déjà une connexion Guac pour cette VM
            cids = get_guac_connection_ids_for_vm(guac_user, vmid)

            # Si pas de connexion existante, on attend l'IP et on crée la connexion
            if not cids:
                ip = get_vm_ip(vmid)  # boucle jusqu'à ce qu'une IP soit trouvée
                if ip:
                    create_guac_connection(
                        guac_user,
                        vmid,
                        ip,
                        current_user.rdp_username,
                        current_user.rdp_password,
                    )
                    cids = get_guac_connection_ids_for_vm(guac_user, vmid)

            if cids:
                guac_url = generate_guac_url(cids[0])

        except Exception as e:
            print(f"[WARN] Problème Guacamole pour VM {vmid} : {e}")

        if guac_url:
            flash(f"Accédez à votre VM via Guacamole : {guac_url}")
        else:
            flash(
                "VM démarrée. Le lien Guacamole apparaîtra quand l'IP sera détectée."
            )

    except Exception as e:
        flash(f"Erreur démarrage ou Guacamole pour VM {vmid} : {str(e)}")

    return redirect(url_for("dashboard"))


@app.route("/stop_vm/<int:vmid>")
@login_required
def stop_vm(vmid):
    """
    - Arrête la VM
    - Supprime la connexion Guacamole associée à cette VM
    """
    proxmox = get_proxmox()
    guac_user = current_user.guac_username

    try:
        proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.stop.post()
        flash(f"VM {vmid} arrêtée avec succès")

        try:
            cids = get_guac_connection_ids_for_vm(guac_user, vmid)
            for cid in cids:
                delete_guac_connection(cid)

            if cids:
                flash(f"Connexion(s) Guacamole {cids} supprimées pour la VM {vmid}.")
        except Exception as e:
            flash(f"VM arrêtée mais erreur suppression Guacamole : {e}")

    except Exception as e:
        flash(f"Erreur arrêt VM {vmid} : {str(e)}")

    return redirect(url_for("dashboard"))


@app.route("/delete_vm/<int:vmid>", methods=["POST"])
@login_required
def delete_vm(vmid):
    """
    Supprime la VM et supprime aussi les connexions Guacamole.
    """
    proxmox = get_proxmox()
    guac_user = current_user.guac_username

    try:
        proxmox.nodes(PROXMOX_NODE).qemu(vmid).delete(purge=1)

        cids = get_guac_connection_ids_for_vm(guac_user, vmid)
        for cid in cids:
            delete_guac_connection(cid)

        if cids:
            flash(f"VM {vmid} et connexion(s) Guacamole {cids} supprimées.")
        else:
            flash(f"VM {vmid} supprimée (aucune connexion Guacamole trouvée).")

    except Exception as e:
        flash(f"Erreur suppression VM {vmid} : {str(e)}")

    return redirect(url_for("dashboard"))


# ============================================================================#
# CREATION DE VM
# ============================================================================#


@app.route("/create_vm", methods=["GET", "POST"])
@login_required
def create_vm():
    """
    - crée uniquement la VM (ISO ou template)
    - l'ajoute au pool de l'utilisateur
    - NE démarre PAS la VM
    - NE crée PAS de connexion Guacamole ici
    """
    proxmox = get_proxmox()
    username = current_user.id
    pool = sanitize_username_base(username)

    if request.method == "POST":
        form_id = request.form.get("form_id")

        # --- Création depuis ISO ---
        if form_id == "iso":
            vmid = int(proxmox.cluster.nextid.get())

            name = request.form.get("name")
            memory = int(request.form.get("memory", 2048))
            cores = int(request.form.get("cores", 2))
            iso = request.form.get("iso")
            ostype = request.form.get("ostype")

            if not name:
                flash("Le nom de la VM est obligatoire.")
                return redirect(url_for("create_vm"))

            try:
                proxmox.nodes(PROXMOX_NODE).qemu.post(
                    vmid=vmid,
                    name=name,
                    pool=pool,
                    memory=memory,
                    cores=cores,
                    net0="virtio,bridge=vmbr0",
                    ide2=str(iso),
                    ostype=str(ostype),
                    scsihw="virtio-scsi-pci",
                    sata0="local-lvm:8",
                    boot="cdn",
                    bootdisk="sata0",
                )

                add_vm_to_pool_if_exists(username, vmid)

                flash(
                    f"VM {vmid} créée avec succès (depuis ISO). "
                    "Vous pouvez maintenant la démarrer depuis le tableau de bord."
                )
                return redirect(url_for("dashboard"))

            except Exception as e:
                flash(f"Erreur création VM : {str(e)}")
                return redirect(url_for("create_vm"))

        # --- Création depuis template ---
        if form_id == "template":
            template = request.form.get("template_vmid")

            try:
                template = int(template)
            except Exception:
                flash("Le VMID du template doit être numérique.")
                return redirect(url_for("create_vm"))

            vmid = int(proxmox.cluster.nextid.get())

            base = sanitize_username_base(username)
            name = f"{base}-pool-vm-{vmid}"

            try:
                proxmox.nodes(PROXMOX_NODE).qemu(template).clone.post(
                    newid=vmid,
                    name=name,
                    pool=pool,
                    full=0,
                )

                add_vm_to_pool_if_exists(username, vmid)

                flash(
                    f"VM {vmid} clonée depuis le template {template}. "
                    f"Nom : {name}. Vous pouvez maintenant la démarrer "
                    "depuis le tableau de bord."
                )
                return redirect(url_for("dashboard"))

            except Exception as e:
                flash(f"Erreur création VM depuis template : {str(e)}")
                return redirect(url_for("create_vm"))

    return render_template("create_vm.html")


# ============================================================================#
# MAIN
# ============================================================================#


if __name__ == "__main__":
    app.config["SESSION_PROTECTION"] = "strong"
    app.run(host="0.0.0.0", port=8081, debug=False)

