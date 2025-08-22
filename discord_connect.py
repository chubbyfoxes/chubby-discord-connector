import discord
from discord.ext import commands, tasks
from web3 import Web3
import os
from dotenv import load_dotenv
import json
from supabase import create_client, Client
import asyncio
import logging
import sys

load_dotenv()

# ----------------- CONFIGURACIÓN DE LOG -----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ----------------- VARIABLES DE ENTORNO -----------------
TOKEN = os.getenv("DISCORD_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
STAKING_CONTRACT = os.getenv("STAKING_CONTRACT")
RPC = os.getenv("RPC")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Validar variables de entorno
missing = []
if not TOKEN:
    missing.append("DISCORD_TOKEN")
if not GUILD_ID:
    missing.append("GUILD_ID")
if not STAKING_CONTRACT:
    missing.append("STAKING_CONTRACT")
if not RPC:
    missing.append("RPC")
if not SUPABASE_URL or not SUPABASE_KEY:
    missing.append("SUPABASE_URL/SUPABASE_KEY")

if missing:
    logger.error("Faltan variables de entorno: %s", ", ".join(missing))
    sys.exit(1)

# GUILD_ID como int
try:
    GUILD_ID = int(GUILD_ID)
except Exception:
    logger.error("GUILD_ID inválido")
    sys.exit(1)

# ----------------- INICIALIZAR BOT -----------------
intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents)

# ----------------- CONEXIÓN WEB3 -----------------
# Use a provider with timeout
w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 60}))

staking_abi = [
    {
        "name": "getAllStakes",
        "outputs": [
            {"name": "stakerAddresses", "type": "address[]"},
            {"name": "nftData", "type": "tuple[][]",
             "components": [
                 {"name": "collection", "type": "address"},
                 {"name": "tokenId", "type": "uint256"},
                 {"name": "timestamp", "type": "uint256"}
             ]
            }
        ],
        "inputs": [
            {"name": "_offset", "type": "uint256"},
            {"name": "_limit", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# Normalize staking contract address (assume 0x-prefixed addresses)
sc_addr = STAKING_CONTRACT
staking = w3.eth.contract(address=w3.to_checksum_address(sc_addr), abi=staking_abi)

# ----------------- SUPABASE -----------------
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Configuración de batching/limites para evitar demasiadas requests
SUPABASE_CHUNK_SIZE = 100
MAX_INDIVIDUAL_LOOKUPS = 5

# Helpers to run blocking supabase/web3 calls in a thread
async def run_blocking(func, *args, **kwargs):
    return await asyncio.to_thread(lambda: func(*args, **kwargs))

async def get_wallet(discord_id: int):
    try:
        res = await run_blocking(lambda: supabase.table("users").select("address").eq("discord_id", str(discord_id)).single().execute())
        if res.data:
            return res.data.get("address")
    except Exception as e:
        logger.exception("Error supabase get_wallet: %s", e)
    return None

async def save_wallet(discord_id: int, wallet: str):
    # Normalize to lowercase before saving to avoid mismatches in queries
    try:
        wallet_norm = wallet.lower()
        await run_blocking(lambda: supabase.table("users").upsert({
            "discord_id": str(discord_id),
            "address": wallet_norm
        }).execute())
        logger.info("Saved wallet for %s as %s", discord_id, wallet_norm)
    except Exception as e:
        logger.exception("Error supabase save_wallet: %s", e)

async def find_discord_id(wallet: str):
    """Return discord_id for a given wallet or None.

    This function performs a safe query that won't raise an exception when
    there are zero (or multiple) rows. It returns the first match as int or
    None if not found.
    """
    try:
        wallet_norm = wallet.lower()
        res = await run_blocking(lambda: supabase.table("users").select("discord_id,address").eq("address", wallet_norm).execute())
        data = getattr(res, "data", None)
        if not data:
            return None
        # data can be a list or a dict depending on driver/version
        if isinstance(data, list):
            if len(data) == 0:
                return None
            return int(data[0].get("discord_id"))
        if isinstance(data, dict):
            return int(data.get("discord_id"))
    except Exception as e:
        logger.exception("Error supabase find_discord_id: %s", e)
    return None

# ----------------- CARGAR REGLAS -----------------
with open("role_rules.json") as f:
    raw_rules = json.load(f)

# Normalizar keys a checksum y normalizar special_ids a ints
ROLE_RULES = {}
for k, v in raw_rules.items():
    try:
        key = k
        addr = w3.to_checksum_address(key)
    except Exception:
        # si la key no es dirección, ignora
        logger.warning("Key en role_rules.json no válida como dirección: %s", k)
        continue
    normalized = {
        "roles": v.get("roles", []),
        "special_ids": {}
    }
    for role_name, ids in v.get("special_ids", {}).items():
        if isinstance(ids, list):
            normalized_ids = []
            for tid in ids:
                try:
                    normalized_ids.append(int(tid))
                except Exception:
                    logger.warning("special_id no convertible a int: %s for %s", tid, k)
            normalized["special_ids"][role_name] = normalized_ids
        else:
            try:
                normalized["special_ids"][role_name] = [int(ids)]
            except Exception:
                logger.warning("special_id no convertible a int: %s for %s", ids, k)
    ROLE_RULES[addr] = normalized

# ----------------- EVENTOS -----------------
@bot.event
async def on_ready():
    logger.info("Bot iniciado como %s", bot.user)
    if not refresh_roles.is_running():
        refresh_roles.start()

# ----------------- COMANDOS -----------------
@bot.command()
async def link(ctx, wallet: str):
    if not w3.is_address(wallet):
        await ctx.send("❌ Wallet inválida")
        return
    wallet = w3.to_checksum_address(wallet)
    await save_wallet(ctx.author.id, wallet)
    await ctx.send(f"✅ {ctx.author.mention} wallet vinculada: {wallet}")

# ----------------- TAREA PARA REFRESCAR ROLES -----------------
@tasks.loop(hours=24)
async def refresh_roles():
    guild = bot.get_guild(GUILD_ID)
    if guild is None:
        try:
            guild = await bot.fetch_guild(GUILD_ID)
        except Exception as e:
            logger.exception("No se pudo obtener el guild: %s", e)
            return

    limit, offset = 100, 0
    safety = 0

    # Fetch all users once and keep a local mapping address(lower)->discord_id
    try:
        logger.info("stage: loading full users mapping from Supabase")
        res_all = await run_blocking(lambda: supabase.table("users").select("discord_id,address").execute())
        mapping_all = {}
        data_all = getattr(res_all, "data", None)
        if data_all:
            for row in (data_all if isinstance(data_all, list) else [data_all]):
                addr = row.get("address")
                did = row.get("discord_id")
                if not addr or not did:
                    continue
                mapping_all[addr.lower()] = int(did)
        logger.info("stage: users_loaded=%s", len(mapping_all))
    except Exception as e:
        logger.exception("No se pudo cargar mapping completo de usuarios: %s", e)
        mapping_all = {}

    while True:
        safety += 1
        if safety > 1000:
            logger.error("Demasiadas iteraciones en paginación, abortando")
            break

        # Fetch stakers once (no retry/backoff to avoid long hangs)
        stakers = stakes = None
        try:
            stakers, stakes = await run_blocking(lambda: staking.functions.getAllStakes(offset, limit).call())
        except Exception as e:
            logger.exception("getAllStakes fallo: %s", e)
            break

        if not stakers:
            break

        # Construir un mapa de roles del guild para evitar buscar repetidamente
        guild_roles_map = {r.name: r for r in guild.roles}

        # Use the preloaded mapping to avoid any Supabase queries during pagination
        stakers_norm = [a.lower() for a in stakers]
        logger.info("stage: processing page offset=%s limit=%s stakers_page=%s", offset, limit, len(stakers_norm))
        # Build subset mapping for this page from the full in-memory mapping
        mapping = {addr: mapping_all.get(addr) for addr in stakers_norm if mapping_all.get(addr) is not None}
        logger.info("stage: mapping entries for page=%s", len(mapping))

        for i, wallet in enumerate(stakers):
            wallet_norm = wallet.lower()
            discord_id = mapping.get(wallet_norm)
            # No individual fallbacks or extra queries — skip if not found
            if not discord_id:
                continue

            member = guild.get_member(discord_id)
            if not member:
                try:
                    member = await guild.fetch_member(discord_id)
                except discord.NotFound:
                    continue
                except Exception as e:
                    logger.exception("Error fetching member %s: %s", discord_id, e)
                    continue

            # STAGE: processing user (concise)
            logger.info("stage: processing user discord_id=%s wallet=%s", discord_id, wallet_norm)

            target_roles = set()
            by_collection = {}

            # Recorre los NFTs staked
            for nft in stakes[i]:
                collection_raw, token_id_raw = nft[0], nft[1]

                try:
                    collection = w3.to_checksum_address(collection_raw)
                except Exception:
                    logger.debug("Dirección colección inválida: %s", collection_raw)
                    continue

                try:
                    token_id = int(token_id_raw)
                except Exception:
                    logger.debug("TokenId no convertible a int: %s", token_id_raw)
                    continue

                if collection not in ROLE_RULES:
                    # STAGE: collection has no rules
                    logger.debug("Colección sin reglas: %s", collection)
                    continue

                by_collection.setdefault(collection, []).append(token_id)

                # IDs especiales
                special_ids = ROLE_RULES[collection].get("special_ids", {})
                for role_name, id_list in special_ids.items():
                    if token_id in id_list:
                        target_roles.add(role_name)

            # Roles por cantidad
            for collection, token_ids in by_collection.items():
                count = len(token_ids)
                # add ALL qualifying roles (not only the highest)
                roles_list = ROLE_RULES[collection].get("roles", [])
                try:
                    sorted_roles = sorted(roles_list, key=lambda r: int(r.get("min", 0)))
                except Exception:
                    sorted_roles = roles_list
                for rule in sorted_roles:
                    try:
                        if count >= int(rule.get("min", 0)):
                            target_roles.add(rule.get("name"))
                    except Exception:
                        continue

            # Todos los roles definidos
            all_defined_roles = set()
            for col in ROLE_RULES.values():
                for r in col.get("roles", []):
                    all_defined_roles.add(r.get("name"))
                # Add the role names defined in special_ids (keys), not the numeric token IDs
                for special_role_name in col.get("special_ids", {}).keys():
                    all_defined_roles.add(special_role_name)

            # Map role names to role objects (if exist in guild)
            name_to_role = {name: guild_roles_map.get(name) for name in all_defined_roles}
            # Filter out None values
            name_to_role = {k: v for k, v in name_to_role.items() if v is not None}

            # Desired role objects
            desired_roles = {name_to_role[name] for name in target_roles if name in name_to_role}

            # STAGE: concise summary of computed roles for this user
            try:
                desired_role_names = [r.name for r in desired_roles]
                logger.info("stage: result %s (%s) -> %s", member.display_name, wallet_norm, desired_role_names)
            except Exception:
                logger.info("stage: result discord_id=%s (%s) -> <could not stringify roles>", discord_id, wallet_norm)

            # Current roles that are managed by our ROLE_RULES set
            managed_roles = set(name_to_role.values())
            current_roles = set(member.roles)

            roles_to_add = desired_roles - current_roles
            roles_to_remove = (managed_roles & current_roles) - desired_roles

            # Permission and hierarchy checks
            bot_member = guild.me
            if bot_member is None:
                bot_member = guild.get_member(bot.user.id)

            can_manage = bot_member and bot_member.guild_permissions.manage_roles
            if not can_manage:
                logger.error("No tengo permisos para gestionar roles en el servidor %s", guild.id)
                return

            filtered_add = set()
            filtered_remove = set()
            for role in roles_to_add:
                if bot_member.top_role.position > role.position:
                    filtered_add.add(role)
                else:
                    logger.warning("No puedo añadir rol %s a %s por jerarquía", role.name, member)
            for role in roles_to_remove:
                if bot_member.top_role.position > role.position:
                    filtered_remove.add(role)
                else:
                    logger.warning("No puedo quitar rol %s a %s por jerarquía", role.name, member)

            # Ejecutar operaciones en batch
            try:
                if filtered_add:
                    await member.add_roles(*sorted(filtered_add, key=lambda r: r.position), reason="Actualización por staking")
                if filtered_remove:
                    await member.remove_roles(*sorted(filtered_remove, key=lambda r: r.position), reason="Actualización por staking")
            except discord.Forbidden:
                logger.exception("Permisos insuficientes gestionando roles para %s", member)
            except discord.HTTPException as e:
                logger.exception("Error HTTP gestionando roles para %s: %s", member, e)

            logger.info("%s (%s) → %s", member.display_name, wallet, [r.name for r in desired_roles])

        offset += limit

# ----------------- RUN -----------------
bot.run(TOKEN)