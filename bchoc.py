#!/usr/bin/env python3

# Unvelivably that line right there ^ caused a lot of headache because I forgot to include it.....
# Generative AI Used: ChatGPT (OpenAI, October 22nd, 2025)
# Purpose: To realize that without "#!/usr/bin/env python3" my code won't run lol
# Prompt: "Can you explain this autograder error given my code:"

import os
import sys
import struct
import time
import uuid
import argparse
from datetime import datetime, timezone
import hashlib
from collections import defaultdict, Counter
from Crypto.Cipher import AES

# -------------------------------------------------------------------------------------------------------------------------
# Constants: Hardcoded password and AES key from assignment.
# -------------------------------------------------------------------------------------------------------------------------

AES_KEY = b"R0chLi4uLi4uLi4=" 
BLOCK_FORMAT = "<32s d 32s 32s 12s 12s 12s I"
BLOCK_HEADER_SIZE = struct.calcsize(BLOCK_FORMAT)
VALID_STATES = {"INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"}
OWNER_ROLES = {"Police", "Lawyer", "Analyst", "Executive"}

PASSWORDS = {
    "Police": os.getenv("BCHOC_PASSWORD_POLICE", ""),
    "Lawyer": os.getenv("BCHOC_PASSWORD_LAWYER", ""),
    "Analyst": os.getenv("BCHOC_PASSWORD_ANALYST", ""),
    "Executive": os.getenv("BCHOC_PASSWORD_EXECUTIVE", ""),
    "Creator": os.getenv("BCHOC_PASSWORD_CREATOR", "")
}

# -------------------------------------------------------------------------------------------------------------------------
# AES Methods
# -------------------------------------------------------------------------------------------------------------------------

# This is a one liner that uses the AES cypher. It's slightly unnecesary but makes the code more readable later
def _aes_cipher():
    return AES.new(AES_KEY, AES.MODE_ECB)

# Unvelivably that line right there ^ caused a lot of headache because I forgot to include it.....
# Generative AI Used: ChatGPT (OpenAI, Oct 30th, 2025)
# Purpose: To rewrite our encrypt and decrypt functions to avoid padding issues
# Prompt: "Do you see an issue with these functions? I'm getting a weird autograder response:"

def aes_encrypt(raw: bytes) -> bytes:
    """Encrypt exactly one 16-byte block (pad with zeros or truncate)."""
    cipher = _aes_cipher()
    if not isinstance(raw, (bytes, bytearray)):
        raw = str(raw).encode()
    if len(raw) < 16:
        raw16 = raw + b"\x00" * (16 - len(raw))
    else:
        raw16 = raw[:16]
    return cipher.encrypt(raw16)
def aes_decrypt(blob: bytes) -> bytes:
    """Decrypt one 16-byte block and return the 16 bytes."""
    cipher = _aes_cipher()
    return cipher.decrypt(blob)

# -------------------------------------------------------------------------------------------------------------------------
# Block Functions
# -------------------------------------------------------------------------------------------------------------------------

# Note: This is basically just unpacking in the "<32s d 32s 32s 12s 12s 12s I" format
def pack_block(prev_hash: bytes, timestamp: float, case_hex: bytes, item_hex: bytes,
               state: bytes, creator: bytes, owner: bytes, data: bytes) -> bytes:
    header = struct.pack(
        BLOCK_FORMAT,
        prev_hash,
        float(timestamp),
        case_hex.ljust(32, b"\0"),
        item_hex.ljust(32, b"\0"),
        state.rstrip(b"\0").ljust(11, b"\0"),
        creator.ljust(12, b"\0"),
        owner.ljust(12, b"\0"),
        len(data)
    )
    return header + data

# Note: Shocker, this is the opposite of the above one lol
def unpack_block_at(f, offset):
    f.seek(offset)
    header = f.read(BLOCK_HEADER_SIZE)
    if not header or len(header) < BLOCK_HEADER_SIZE:
        return None, None, None
    fields = struct.unpack(BLOCK_FORMAT, header)
    data_len = fields[-1]
    data = f.read(data_len)
    return fields, data, f.tell()

# -------------------------------------------------------------------------------------------------------------------------
# Picking a file from the right source
# -------------------------------------------------------------------------------------------------------------------------

# Note: This is modified code from a work project, easy
def bc_path():
    path = os.getenv("BCHOC_FILE_PATH")
    if not path:
        print("BCHOC_FILE_PATH not set", file=sys.stderr)
        sys.exit(1)
    return path

# -------------------------------------------------------------------------------------------------------------------------
# Creating the initial block
# -------------------------------------------------------------------------------------------------------------------------

# Generative AI Used: ChatGPT (OpenAI, Oct 3rd, 2025)
# Purpose: To figure out why our initial block was having errors
# Prompt: "Can you explain why I'm not able to create a block with the right values?"

def create_initial_block_bytes():
    prev_hash = b"\0" * 32
    timestamp = 0.0
    # Must use ASCII '0' to satisfy binary specs, even though it breaks simple decryption
    case_hex = b"0" * 32
    item_hex = b"0" * 32
    state = b"INITIAL" + b"\0" * (12 - len("INITIAL"))
    creator = b"\0" * 12
    owner = b"\0" * 12
    data = b"Initial block\0"
    return pack_block(prev_hash, timestamp, case_hex, item_hex, state, creator, owner, data)

# -------------------------------------------------------------------------------------------------------------------------
# Creating the initial block
# -------------------------------------------------------------------------------------------------------------------------

# Note: This code isn't great so I put it as a method. It works as a way to rederive values from the blocks
def read_all_blocks_raw(path):
    blocks = []
    if not os.path.exists(path):
        return blocks
    with open(path, "rb") as f:
        offset = 0
        while True:
            header = f.read(BLOCK_HEADER_SIZE)
            if not header:
                break
            if len(header) < BLOCK_HEADER_SIZE:
                print("> Incomplete block header", file=sys.stderr)
                sys.exit(1)
            fields = struct.unpack(BLOCK_FORMAT, header)
            data_len = fields[-1]
            data = f.read(data_len)
            if len(data) < data_len:
                print("> Incomplete block data", file=sys.stderr)
                sys.exit(1)
            raw = header + data
            blocks.append((fields, data, offset, raw))
            offset += len(raw)
    return blocks

# -------------------------------------------------------------------------------------------------------------------------
# Hashing
# -------------------------------------------------------------------------------------------------------------------------

# If we ever get the issue where every block is suddenly giberesh, check here first
def block_hash_bytes(raw_bytes: bytes) -> bytes:
    return hashlib.sha256(raw_bytes).digest()
def block_hash_hex(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()

# -------------------------------------------------------------------------------------------------------------------------
# AES-encoded field helpers
# -------------------------------------------------------------------------------------------------------------------------

# Idea: Here’s the idea: case IDs and item IDs need to appear in the blockchain, but not in plaintext
# Note: This isnt stored in plaintext, the helpers take UUID or int to pack into an AES block, so its encrypted

def caseid_to_hex_encrypted(case_uuid: uuid.UUID) -> bytes:
    enc = aes_encrypt(case_uuid.bytes)  
    return enc.hex().encode()

def itemid_to_hex_encrypted(itemid: int) -> bytes:
    buf = bytearray(16)
    buf[12:16] = itemid.to_bytes(4, "big")
    enc = _aes_cipher().encrypt(bytes(buf))
    return enc.hex().encode()

def hex_enc_to_caseid(hex_bytes: bytes):
    try:
        raw = bytes.fromhex(hex_bytes.decode().rstrip("\0"))
        dec = aes_decrypt(raw)
        if len(dec) == 16:
            return str(uuid.UUID(bytes=dec))
    except Exception:
        return None
    return None

def hex_enc_to_itemid(hex_bytes: bytes):
    try:
        raw = bytes.fromhex(hex_bytes.decode().rstrip("\0"))
        dec = aes_decrypt(raw)
        return int.from_bytes(dec[12:16], "big")
    except Exception:
        return None


# -------------------------------------------------------------------------------------------------------------------------
# Password helpers
# -------------------------------------------------------------------------------------------------------------------------

# Figures out user given password

# Generative AI Used: ChatGPT (OpenAI, Oct 30th, 2025)
# Purpose: Refactor our massive password logic and figure out why tests were failing
# Prompt: "Do you see anything obviously wrong with our logic? Why are we failing these test cases?"

def role_for_password(pw: str):
    for r, v in PASSWORDS.items():
        if v and pw == v:
            return r
    return None

def require_creator_password(pw: str):
    role = role_for_password(pw)
    if role != "Creator":
        print("> Invalid password")
        sys.exit(1)
    return role

def require_owner_or_creator_password(pw: str):
    role = role_for_password(pw)
    if role is None:
        print("> Invalid password")
        sys.exit(1)
    return role

# -------------------------------------------------------------------------------------------------------------------------
# File append helper
# -------------------------------------------------------------------------------------------------------------------------

# Adds to block chain, yay
def append_block_to_file(path, block_bytes):
    with open(path, "ab") as f:
        f.write(block_bytes)

# -------------------------------------------------------------------------------------------------------------------------
# Build a block from elements
# -------------------------------------------------------------------------------------------------------------------------

# Similar to pack_block, but with less nonsense. Basically just a wrapper to do "<32s d 32s 32s 12s 12s 12s"

def build_block(prev_hash: bytes, case_hex: bytes, item_hex: bytes,
                state_text: str, creator_text: str, owner_text: str, data_text: str):
    timestamp = time.time()
    return pack_block(prev_hash, timestamp,
                      case_hex, item_hex,
                      state_text.encode(),
                      creator_text.encode(),
                      owner_text.encode(),
                      data_text.encode())

# -------------------------------------------------------------------------------------------------------------------------
# Initialize / cmd_init
# -------------------------------------------------------------------------------------------------------------------------

# When the blockchain file doesn’t exist (or is empty), we create a fresh block

def cmd_init(args):
    path = bc_path()
    if not os.path.exists(path):
        initial = create_initial_block_bytes()
        with open(path, "wb") as f:
            f.write(initial)
        print("> Blockchain file not found. Created INITIAL block.")
        return 0

    blocks = read_all_blocks_raw(path)
    if len(blocks) == 0:
        initial = create_initial_block_bytes()
        with open(path, "wb") as f:
            f.write(initial)
        print("> Blockchain file not found. Created INITIAL block.")
        return 0

    print("> Blockchain file found with INITIAL block.")
    return 0


# -------------------------------------------------------------------------------------------------------------------------
# Chain validation (verify)
# -------------------------------------------------------------------------------------------------------------------------

# Ok this is where stuff get's more complicated. This section checks to ensure the chain is valid, so that there's no illigal tampering

# Generative AI Used: ChatGPT (OpenAI, Oct 16th, 2025)
# Purpose: This code was slowly added to until no one understood it, so we used AI to explain it haha
# Prompt: "Refactor our code and add tons of comments so it's easy so see what does what"

def validate_chain(blocks):
    n = len(blocks)
    if n == 0:
        return False, {"msg": "No blocks"}

    # --- Validate the genesis block ---
    fields0, data0, _, raw0 = blocks[0]
    prev0 = fields0[0]
    ts0 = fields0[1]

    # The initial block is always zero-hash, timestamp 0, and a specific label.
    if prev0 != b"\0" * 32 or ts0 != 0.0 or data0 != b"Initial block\0":
        badhash = block_hash_hex(raw0)
        return False, {"type": "invalid_initial", "bad": badhash}

    # Precompute hash of every block for convenience
    hashes = [block_hash_hex(raw) for (_, _, _, raw) in blocks]

    # --- Check for forks: no parent hash should appear more than once ---
    parent_count = Counter()
    for i in range(1, n):
        fields_i = blocks[i][0]
        prev = fields_i[0]
        parent_count[prev] += 1

    for p, cnt in parent_count.items():
        if p != b"\0" * 32 and cnt > 1:
            # This means the chain has branched, which is not allowed.
            for i in range(1, n):
                if blocks[i][0][0] == p:
                    bad = block_hash_hex(blocks[i][3])
                    parent_hash_hex = p.hex()
                    return False, {"type": "duplicate_parent", "bad": bad, "parent": parent_hash_hex}

    # --- Check that every block points to the correct previous hash ---
    for i in range(1, n):
        prev = blocks[i][0][0]
        expected_prev = bytes.fromhex(hashes[i - 1])
        if prev != expected_prev:
            # The block is claiming a parent that doesn’t match the actual hash
            # of the block before it, so the chain is broken.
            bad = block_hash_hex(blocks[i][3])
            parent_hex = prev.hex()

            # Try to see if the parent exists somewhere else in the chain.
            found = False
            for j in range(n):
                if block_hash_hex(blocks[j][3]) == parent_hex:
                    found = True
                    parent = parent_hex
                    break

            if not found:
                parent = "NOT FOUND"

            return False, {"type": "bad_parent", "bad": bad, "parent": parent}

    # --- Validate per-item state progression ---
    item_last_state = {}

    for i, (fields, data, off, raw) in enumerate(blocks):
        state = fields[4].decode().rstrip("\0")
        itemid = hex_enc_to_itemid(fields[3])

        # Skip genesis block
        if i == 0:
            continue

        if itemid is None:
            continue

        prev_state = item_last_state.get(itemid, None)

        # First appearance of an item must be CHECKEDIN
        if prev_state is None:
            if state != "CHECKEDIN":
                bad = block_hash_hex(raw)
                return False, {"type": "invalid_transition_first", "bad": bad}
            item_last_state[itemid] = "CHECKEDIN"
            continue

        # Once removed/disposed/destroyed, no further transitions allowed
        if prev_state in {"DISPOSED", "DESTROYED", "RELEASED"}:
            bad = block_hash_hex(raw)
            return False, {"type": "action_after_remove", "bad": bad}

        # If the item was checked in previously
        if prev_state == "CHECKEDIN":
            if state == "CHECKEDOUT":
                item_last_state[itemid] = "CHECKEDOUT"
            elif state == "CHECKEDIN":
                bad = block_hash_hex(raw)
                return False, {"type": "double_checkin_or_invalid", "bad": bad}
            elif state in {"DISPOSED", "DESTROYED", "RELEASED"}:
                item_last_state[itemid] = state
            else:
                bad = block_hash_hex(raw)
                return False, {"type": "invalid_transition", "bad": bad}

        # If the item was checked out previously
        elif prev_state == "CHECKEDOUT":
            if state == "CHECKEDIN":
                item_last_state[itemid] = "CHECKEDIN"
            elif state == "CHECKEDOUT":
                bad = block_hash_hex(raw)
                return False, {"type": "double_checkout", "bad": bad}
            elif state in {"DISPOSED", "DESTROYED", "RELEASED"}:
                # Items may not be destroyed while still checked out
                bad = block_hash_hex(raw)
                return False, {"type": "remove_while_checkedout", "bad": bad}
            else:
                bad = block_hash_hex(raw)
                return False, {"type": "invalid_transition", "bad": bad}

        else:
            bad = block_hash_hex(raw)
            return False, {"type": "invalid_transition_unknown", "bad": bad}

    return True, {}

# -------------------------------------------------------------------------------------------------------------------------
# Commands: Password validation is handled when running a command
# -------------------------------------------------------------------------------------------------------------------------

# Note: The commands section is SO LONG that I'm splitting it up and giving sub headers

# -------------------------------------------------------------------------------------------------------------------------
# Command add creates a new CHECKEDIN block given IDs
# -------------------------------------------------------------------------------------------------------------------------

def cmd_add(args):
    if not args.c or not args.i or not args.g or not args.p:
        print("> Missing parameter")
        sys.exit(1)

    require_creator_password(args.p)

    try:
        case_uuid = uuid.UUID(args.c)
    except Exception:
        print("> Invalid case id")
        sys.exit(1)

    path = bc_path()

    # Create INITIAL block if there isn't one
    if not os.path.exists(path):
        initial = create_initial_block_bytes()
        with open(path, "wb") as f:
            f.write(initial)
        print("> Blockchain file not found. Created INITIAL block.")

    blocks = read_all_blocks_raw(path)
    existing_items = set()
    removed_items = set()
    seen_in_this_command = set()

    # Note: Bug fixed here by skipping block one, look for similar issues in other places
    for idx, (fields, data, off, raw) in enumerate(blocks):
        if idx == 0: 
            continue
        itemid = hex_enc_to_itemid(fields[3])
        state = fields[4].decode().rstrip("\0")
        if itemid is None:
            continue

        existing_items.add(itemid)
        if state in {"DISPOSED", "DESTROYED", "RELEASED"}:
            removed_items.add(itemid)

    # Get the previous has, then flatten the input bc of argparse
    if len(blocks) <= 1:
        last_hash = b"\0" * 32
    else:
        last_hash = block_hash_bytes(blocks[-1][3])
    item_list = []
    for entry in args.i:
        if isinstance(entry, list):
            item_list.extend(entry)
        else:
            item_list.append(entry)

    for item in item_list:
        try:
            item_int = int(item)
            if item_int < 0 or item_int > 0xFFFFFFFF:
                raise ValueError()
        except:
            print("> Invalid item id")
            sys.exit(1)

        # Generative AI Used: ChatGPT (OpenAI, Oct 16th, 2025)
        # Purpose: AI recomended bug fix for why we would get repeated blocks, this fixes it at the source
        # Prompt: "Is there a simple way to stop our code from having cloned blocks?"

        if item_int in existing_items:
            print("> Item id already exists")
            sys.exit(1)
        if item_int in removed_items:
            print("> Item id already exists (removed previously)")
            sys.exit(1)
        if item_int in seen_in_this_command:
            print("> Item id already exists")
            sys.exit(1)
        seen_in_this_command.add(item_int)
        case_hex = caseid_to_hex_encrypted(case_uuid)
        item_hex = itemid_to_hex_encrypted(item_int)
        state = "CHECKEDIN"
        creator = args.g[:12]
        owner_role = ""
        block_raw = build_block(last_hash, case_hex, item_hex, state, creator, owner_role, "")
        append_block_to_file(path, block_raw)
        last_hash = block_hash_bytes(block_raw)
        print(f"> Added item: {item_int}")
        print("> Status: CHECKEDIN")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        print(f"> Time of action: {now}")
    return 0

# -------------------------------------------------------------------------------------------------------------------------
# CHECKOUT: Sets block to CHECKEDOUT by creating a new block
# -------------------------------------------------------------------------------------------------------------------------

def cmd_checkout(args):
    if not args.i or not args.p:
        print("> Missing parameter")
        sys.exit(1)
    role = require_owner_or_creator_password(args.p)
    path = bc_path()
    if not os.path.exists(path):
        initial = create_initial_block_bytes()
        with open(path, "wb") as f:
            f.write(initial)
    blocks = read_all_blocks_raw(path)

    # This didn't end up fixing the failed test, but worth keeping, try it is other areas
    try:
        item_int = int(args.i)
    except:
        print("> Invalid item id")
        sys.exit(1)

    item_history = []
    last_state = None
    creator_from_add = None
    case_hex = None

    # Generative AI Used: ChatGPT (OpenAI, Oct 16th, 2025)
    # Purpose: I was struggling to write this section with no edge case failure
    # Prompt: "Why isn't my code working?"

    for idx, (fields, data, off, raw) in enumerate(blocks):
        if idx == 0:
            continue
        if hex_enc_to_itemid(fields[3]) == item_int:
            item_history.append((idx, fields))
            last_state = fields[4].decode().rstrip("\0")
            if creator_from_add is None:
                creator_from_add = fields[5].decode().rstrip("\0")
            if case_hex is None:
                case_hex = fields[2]

    # Item must exist and be CHECKEDIN
    if not item_history:
        print("> Item not found")
        sys.exit(1)
    if last_state != "CHECKEDIN":
        print("> Cannot checkout: item not checked in")
        sys.exit(1)

    # Previous hash for new block
    if len(item_history) == 1:
        prev_hash = b"\0" * 32
    else:
        prev_hash = block_hash_bytes(blocks[-1][3])

    item_hex = itemid_to_hex_encrypted(item_int)
    owner_text = role.upper()

    block_raw = build_block(prev_hash, case_hex, item_hex,
                            "CHECKEDOUT", creator_from_add, owner_text, "")
    append_block_to_file(path, block_raw)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    caseid_str = hex_enc_to_caseid(case_hex)
    if caseid_str:
        print(f"> Case: {caseid_str}")
    print(f"> Checked out item: {item_int}")
    print("> Status: CHECKEDOUT")
    print(f"> Time of action: {now}")
    return 0

# -------------------------------------------------------------------------------------------------------------------------
# CHECKIN: Marks item as CHECKEDIN by creating a new block, kinda the same as the last one
# -------------------------------------------------------------------------------------------------------------------------
def cmd_checkin(args):
    if not args.i or not args.p:
        print("> Missing parameter")
        sys.exit(1)
    role = require_owner_or_creator_password(args.p)
    path = bc_path()

    # Note: We could probably combine this with the earlier commands since this is reused code, but it's readable so we can leave it

    if not os.path.exists(path):
        initial = create_initial_block_bytes()
        with open(path, "wb") as f:
            f.write(initial)
    blocks = read_all_blocks_raw(path)

    # Parse item id
    try:
        item_int = int(args.i)
    except:
        print("> Invalid item id")
        sys.exit(1)

    # Search chain for item already being there so we can get the item's history
    item_history = []
    last_state = None
    creator_from_add = None
    case_hex = None
    for idx, (fields, data, off, raw) in enumerate(blocks):
        if idx == 0:
            continue
        if hex_enc_to_itemid(fields[3]) == item_int:
            item_history.append((idx, fields))
            last_state = fields[4].decode().rstrip("\0")
            if creator_from_add is None:
                creator_from_add = fields[5].decode().rstrip("\0")
            if case_hex is None:
                case_hex = fields[2]
    if not item_history:
        print("> Item not found")
        sys.exit(1)
    if last_state != "CHECKEDOUT":
        print("> Cannot checkin: item not checked out")
        sys.exit(1)

    # Generative AI Used: ChatGPT (OpenAI, Oct 12th, 2025)
    # Purpose: Get the hash value given the item history
    # Prompt: "I'm struggling to generate a hash when I have the item history and item info, why isn't this working?"

    if len(item_history) == 1:
        prev_hash = b"\0" * 32
    else:
        prev_hash = block_hash_bytes(blocks[-1][3])
    item_hex = itemid_to_hex_encrypted(item_int)
    owner_text = role.upper()
    block_raw = build_block(prev_hash, case_hex, item_hex, "CHECKEDIN", creator_from_add, owner_text, "")
    append_block_to_file(path, block_raw)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    caseid_str = hex_enc_to_caseid(case_hex)
    if caseid_str:
        print(f"> Case: {caseid_str}")
    print(f"> Checked in item: {item_int}")
    print("> Status: CHECKEDIN")
    print(f"> Time of action: {now}")
    return 0

# -------------------------------------------------------------------------------------------------------------------------
# SHOW CASES: This just lists all the cases, except for the 0s, amazing for debugging
# -------------------------------------------------------------------------------------------------------------------------

def cmd_show_cases(args):
    path = bc_path()
    blocks = read_all_blocks_raw(path)
    seen = set()

    for idx, (fields, data, off, raw) in enumerate(blocks):
        if idx == 0:
            continue
        case_hex = fields[2]
        caseid = hex_enc_to_caseid(case_hex)
        if not caseid or caseid == "00000000-0000-0000-0000-000000000000":
            continue
        seen.add(caseid)

    for x in sorted(seen):
        print(x)
    return 0

# -------------------------------------------------------------------------------------------------------------------------
# SHOW ITEMS: Lists all items that are specifically related to a caseID, kinda self explanatory 
# -------------------------------------------------------------------------------------------------------------------------

def cmd_show_items(args):
    if not args.c:
        print("> Missing case id")
        sys.exit(1)

    if args.p:
        _ = require_owner_or_creator_password(args.p)

    try:
        case_uuid = uuid.UUID(args.c)
    except:
        print("> Invalid case id")
        sys.exit(1)

    path = bc_path()
    blocks = read_all_blocks_raw(path)

    items = set()
    for idx, (fields, data, off, raw) in enumerate(blocks):
        if idx == 0:
            continue
        case_hex = fields[2]
        caseid = hex_enc_to_caseid(case_hex)
        if caseid == str(case_uuid):
            itemid = hex_enc_to_itemid(fields[3])
            if itemid is not None:
                items.add(itemid)

    for it in items:
        print(it)
    return 0

# -------------------------------------------------------------------------------------------------------------------------
# SHOW HISTORY: Displays the entire blockchain
# -------------------------------------------------------------------------------------------------------------------------

# Note: This can be filtered by case if we want that
def cmd_show_history(args):

    role = require_owner_or_creator_password(args.p)
    path = bc_path()
    blocks = read_all_blocks_raw(path)
    entries = []
    for idx, (fields, data, off, raw) in enumerate(blocks):

        # Genesis block is a special case
        if idx == 0:
            caseid = "00000000-0000-0000-0000-000000000000"
            itemid = 0
        else:
            caseid = hex_enc_to_caseid(fields[2])
            itemid = hex_enc_to_itemid(fields[3])

        # Generative AI Used: ChatGPT (OpenAI, Oct 30th, 2025)
        # Purpose: Get the timestamp to be formatted in the way the autograder wants
        # Prompt: "Why is the autograder unhappy with my timestamp generation?"

        state = fields[4].decode().rstrip("\0")
        ts = fields[1]
        if ts == 0.0:
            timestr = "1970-01-01T00:00:00Z"
        else:
            timestr = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")

        entries.append((idx, caseid, itemid, state, timestr, fields, raw))

    # Here's a case filter and item filter, I don't know if we need it but its nice for testing
    if args.c:
        try:
            cu = str(uuid.UUID(args.c))
        except:
            print("> Invalid case id")
            sys.exit(1)
        entries = [e for e in entries if e[1] == cu]
    if args.i:
        try:
            iid = int(args.i)
        except:
            print("> Invalid item id")
            sys.exit(1)
        entries = [e for e in entries if e[2] == iid]

    # Reverse ordering so that it makes sense
    if getattr(args, "reverse", False):
        entries = list(reversed(entries))
    if args.n:
        try:
            n = int(args.n)
            entries = entries[:n]
        except:
            pass

    # Print the history
    for (_, caseid, itemid, state, timestr, fields, raw) in entries:
        print(f"> Case: {caseid}")
        print(f"> Item: {itemid}")
        print(f"> Action: {state}")
        print(f"> Time: {timestr}")
        print("")
    return 0

# -------------------------------------------------------------------------------------------------------------------------
# REMOVE: If you're a creator, and the item is checked in, you can mark it DISPOSED / DESTROYED / RELEASED.
# -------------------------------------------------------------------------------------------------------------------------

def cmd_remove(args):
    if not args.i or not args.why or not args.p:
        print("> Missing parameter")
        sys.exit(1)

    require_creator_password(args.p)
    reason = args.why
    if reason not in {"DISPOSED", "DESTROYED", "RELEASED"}:
        print("> Invalid reason")
        sys.exit(1)

    # Parse item id
    try:
        item_int = int(args.i)
    except:
        print("> Invalid item id")
        sys.exit(1)

    # This can be the first thing run, so I copied over the init script
    path = bc_path()
    if not os.path.exists(path):
        print("> Blockchain not initialized")
        sys.exit(1)

    # Same item history as above
    blocks = read_all_blocks_raw(path)
    item_history = []
    last_state = None
    creator_from_add = None
    case_hex = None
    owner_from_last = None
    for idx, (fields, data, off, raw) in enumerate(blocks):
        if idx == 0:
            continue
        if hex_enc_to_itemid(fields[3]) == item_int:
            item_history.append((idx, fields))
            last_state = fields[4].decode().rstrip("\0")
            if creator_from_add is None:
                creator_from_add = fields[5].decode().rstrip("\0")
            if case_hex is None:
                case_hex = fields[2]
            owner_candidate = fields[6].decode().rstrip("\0")
            if owner_candidate:
                owner_from_last = owner_candidate

    # If the item exists and is CHECKEDIN, you can make a block to delete it
    if not item_history:
        print("> Item not found")
        sys.exit(1)
    if last_state != "CHECKEDIN":
        print("> Item must be CHECKEDIN to remove")
        sys.exit(1)
    prev_hash = b"\0" * 32
    item_hex = itemid_to_hex_encrypted(item_int)
    owner_bytes = owner_from_last.encode().ljust(12, b"\0") if owner_from_last else b"\0" * 12
    state_bytes = reason.encode()
    creator_bytes = creator_from_add.encode() if creator_from_add else b"\0" * 12
    data = b""
    timestamp = time.time()
    block_bytes = pack_block(prev_hash, timestamp, case_hex, item_hex,
                             state_bytes, creator_bytes, owner_bytes, data)
    append_block_to_file(path, block_bytes)
    print(f"> Removed item: {item_int}")
    print(f"> Reason: {reason}")
    return 0

# -------------------------------------------------------------------------------------------------------------------------
# VERIFY: Validates the blockchain for structural and logical consistency
# -------------------------------------------------------------------------------------------------------------------------

def cmd_verify(args):
    path = bc_path()
    blocks = read_all_blocks_raw(path)
    n = len(blocks)
    print(f"> Transactions in blockchain: {n}")

    # Validate using validate_chain
    ok, info = validate_chain(blocks)

    if ok:
        print("> State of blockchain: CLEAN")
        return 0
    else:
        print("> State of blockchain: ERROR")
        t = info.get("type", None)

        # Generative AI Used: ChatGPT (OpenAI, Oct 12th, 2025)
        # Purpose: Help make sure every failcase is represented and handles
        # Prompt: "Given the "validate_chain()" block, can you write something that helps if it ever fails?"

        if t == "invalid_initial":
            print(f"> Bad block: {info.get('bad')}")
            return 1

        if t == "bad_parent":
            print(f"> Bad block: {info.get('bad')}")
            parent = info.get("parent")
            if parent == "NOT FOUND":
                print(f"> Parent block: NOT FOUND")
            else:
                print(f"> Parent block: {parent}")
            return 1

        if t == "duplicate_parent":
            print(f"> Bad block: {info.get('bad')}")
            print(f"> Parent block: {info.get('parent')}")
            return 1

        if t in {"invalid_transition_first", "action_after_remove", "double_checkin_or_invalid",
                 "double_checkout", "remove_while_checkedout", "invalid_transition",
                 "invalid_transition_unknown"}:
            print(f"> Bad block: {info.get('bad')}")
            return 1

        print("> Bad block: unknown")
        return 1

# -------------------------------------------------------------------------------------------------------------------------
# SUMMARY: Shows a per-case overview of evidence items and their states
# -------------------------------------------------------------------------------------------------------------------------

def cmd_summary(args):

    # Case ID is required
    if not args.c:
        print("> Missing case id")
        sys.exit(1)

    # Validate case UUID format
    try:
        case_uuid = uuid.UUID(args.c)
    except:
        print("> Invalid case id")
        sys.exit(1)

    path = bc_path()
    blocks = read_all_blocks_raw(path)

    # Go through all the blocks keeping a talley of what types we hit, counting only blocks for the right case
    items_set = set()
    counts = {"CHECKEDIN": 0, "CHECKEDOUT": 0, "DISPOSED": 0, "DESTROYED": 0, "RELEASED": 0}
    for idx, (fields, data, off, raw) in enumerate(blocks):
        if idx == 0:
            continue

        caseid = hex_enc_to_caseid(fields[2])
        itemid = hex_enc_to_itemid(fields[3])
        state = fields[4].decode().rstrip("\0")
        if caseid == str(case_uuid):
            if itemid is not None:
                items_set.add(itemid)
            if state in counts:
                counts[state] += 1

    print(f"Case Summary for Case ID: {case_uuid}")
    print(f"Total Evidence Items: {len(items_set)}")
    print(f"Checked In: {counts['CHECKEDIN']}")
    print(f"Checked Out: {counts['CHECKEDOUT']}")
    print(f"Disposed: {counts['DISPOSED']}")
    print(f"Destroyed: {counts['DESTROYED']}")
    print(f"Released: {counts['RELEASED']}")
    return 0

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Main
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# For better or for worse we made everything a function instead of a file. I hope that doesn't end up being a problem...

def main():

    # Generative AI Used: ChatGPT (OpenAI, Oct 30th, 2025)
    # Purpose: Help with the add_argument syntax
    # Prompt: "I've never worked with this type of thing in python, given the instruction details how would you do check the args?"

    parser = argparse.ArgumentParser(prog="bchoc")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("init")
    ap = sub.add_parser("add")
    ap.add_argument("-c")
    ap.add_argument("-i", action="append")
    ap.add_argument("-g")
    ap.add_argument("-p")
    cp = sub.add_parser("checkout")
    cp.add_argument("-i")
    cp.add_argument("-p")
    cip = sub.add_parser("checkin")
    cip.add_argument("-i")
    cip.add_argument("-p")
    show = sub.add_parser("show")
    show_sub = show.add_subparsers(dest="showcmd")
    sc = show_sub.add_parser("cases")
    sc.add_argument("-p", required=False)
    si = show_sub.add_parser("items")
    si.add_argument("-c", required=True)
    si.add_argument("-p", required=False)
    sh2 = show_sub.add_parser("history")
    sh2.add_argument("-c", required=False)
    sh2.add_argument("-i", required=False)
    sh2.add_argument("-n", required=False)
    sh2.add_argument("-r", "--reverse", action="store_true")
    sh2.add_argument("-p", required=True)
    hist = sub.add_parser("history")
    hist.add_argument("-c", required=False)
    hist.add_argument("-i", required=False)
    hist.add_argument("-n", required=False)
    hist.add_argument("-r", "--reverse", action="store_true")
    hist.add_argument("-p", required=True)
    remove = sub.add_parser("remove")
    remove.add_argument("-i")
    remove.add_argument("--why", "-y")
    remove.add_argument("-p")
    remove.add_argument("-o", required=False)
    sub.add_parser("verify")
    summ = sub.add_parser("summary")
    summ.add_argument("-c")
    summ.add_argument("-p")
    args, unknown = parser.parse_known_args()
    argv = sys.argv
    if len(argv) >= 3 and argv[1] == "show" and argv[2] == "history":
        ph = argparse.ArgumentParser()
        ph.add_argument("-c", required=False)
        ph.add_argument("-i", required=False)
        ph.add_argument("-n", required=False)
        ph.add_argument("-r", "--reverse", action="store_true")
        ph.add_argument("-p", required=True)
        hargs = ph.parse_args(argv[3:])
        return cmd_show_history(hargs)
    if len(argv) >= 3 and argv[1] == "show" and argv[2] == "cases":
        ph = argparse.ArgumentParser()
        ph.add_argument("-p", required=False)
        hargs = ph.parse_args(argv[3:])
        return cmd_show_cases(hargs)
    if len(argv) >= 3 and argv[1] == "show" and argv[2] == "items":
        ph = argparse.ArgumentParser()
        ph.add_argument("-c", required=True)
        ph.add_argument("-p", required=False)
        hargs = ph.parse_args(argv[3:])
        return cmd_show_items(hargs)
    if args.command == "init":
        if len(sys.argv) != 2:
            print("> Invalid usage of init")
            sys.exit(1)
        return cmd_init(args)
    if args.command == "add":
        return cmd_add(args)
    if args.command == "checkout":
        return cmd_checkout(args)
    if args.command == "checkin":
        return cmd_checkin(args)
    if args.command == "history":
        return cmd_show_history(args)
    if args.command == "remove":
        return cmd_remove(args)
    if args.command == "verify":
        return cmd_verify(args)
    if args.command == "summary":
        return cmd_summary(args)
    parser.print_help()
    sys.exit(1)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Run
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Note: There was one line here written by chatGPT, but it's only because I was dumb
if __name__ == "__main__":
    try:
        rc = main()
        if rc is None:
            rc = 0
        sys.exit(rc)
    except SystemExit:
        raise
    except Exception as e:
        print(f"> Error: {e}", file=sys.stderr)
        sys.exit(1)
