#!/usr/bin/env python3
"""
Single-file crypto injector application.

Usage:
  - This file serves two roles:
    1) When imported by `mitmdump -s crypto_injector_app.py` it exposes the
       `request(flow)` and `response(flow)` functions used by mitmproxy.
    2) When run directly, it starts a Windows tray app that: requests
       elevation, sets the Windows proxy to 127.0.0.1:8080, spawns mitmdump
       with this file as the addon, and provides a hidden UI that appears
       on Ctrl+A to manage injected addresses.

Notes:
  - You must have `mitmdump` (from mitmproxy) installed and on PATH.
  - Install required Python packages: see `requirements.txt`.
"""
import os
import json
import time
import random
import hashlib

# ------------------------
# Addon code (import-safe)
# ------------------------
# The functions below are intentionally free of GUI imports so mitmdump
# can import this module without needing the GUI dependencies.

transaction_cache = {}
last_file_mtime = 0

eth_address_mappings = []
sol_address_mappings = []

# When the GUI is running it will optionally serve transactions via a
# simple local HTTP server. The mitmdump addon (separate process) will
# query that server when available. This avoids writing transactions to
# disk while the GUI is open; state lives in-memory and disappears on
# exit.

def load_address_mappings():
    """Load ETH and SOL address mappings from `injected_crypto.json`"""
    global eth_address_mappings, sol_address_mappings
    eth_address_mappings = []
    sol_address_mappings = []
    try:
        # Prefer remote (GUI) state when available. The GUI exposes a
        # simple HTTP server and provides its port via the
        # `INJECTOR_PORT` environment variable. Fall back to a local
        # JSON file if the GUI isn't running.
        transactions = None
        try:
            port = os.environ.get('INJECTOR_PORT')
            if port:
                import urllib.request
                # ensure we do NOT use the system proxy for localhost requests
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f'http://127.0.0.1:{port}/state', timeout=0.5) as resp:
                    data = json.load(resp)
                    transactions = data.get('transactions')
        except Exception:
            transactions = None

        if transactions is None and os.path.exists('injected_crypto.json'):
            with open('injected_crypto.json', 'r') as f:
                transactions = json.load(f)

        if transactions:
            for tx in transactions:
                crypto = (tx.get('crypto') or '').upper()
                if crypto == 'ETH':
                    eth_address_mappings.append({
                        'your_address': (tx.get('your_address') or '').lower(),
                        'rich_address': (tx.get('rich_address') or '').lower()
                    })
                elif crypto == 'SOL':
                    sol_address_mappings.append({
                        'your_address': tx.get('your_address'),
                        'rich_address': tx.get('rich_address')
                    })
    except Exception as e:
        print(f"Error loading address mappings: {e}")

def get_transaction_id(address, amount, sender, crypto):
    unique_string = f"{crypto}{address}{amount}{sender}"
    return hashlib.sha256(unique_string.encode()).hexdigest()

def load_injected_transactions(crypto_type):
    global transaction_cache, last_file_mtime
    try:
        # Try remote GUI state first (in-memory while GUI is open).
        ui_transactions = None
        try:
            port = os.environ.get('INJECTOR_PORT')
            if port:
                import urllib.request
                # avoid proxying this request through mitmdump itself
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f'http://127.0.0.1:{port}/state', timeout=0.5) as resp:
                    data = json.load(resp)
                    ui_transactions = data.get('transactions')
        except Exception:
            ui_transactions = None

        # Fall back to file-based transactions for compatibility if no
        # GUI is serving state. If we got remote UI transactions above
        # (via the injector HTTP server) we will process those directly.
        if ui_transactions is None:
            if not os.path.exists('injected_crypto.json'):
                return []
            current_mtime = os.path.getmtime('injected_crypto.json')
            if current_mtime == last_file_mtime and transaction_cache:
                return [tx for tx in transaction_cache.values() if tx.get('_crypto_type') == crypto_type]
            last_file_mtime = current_mtime
            with open('injected_crypto.json', 'r') as f:
                ui_transactions = json.load(f)

        # Now we have `ui_transactions` either from the GUI HTTP server
        # or from the file fallback. Normalize and convert into the
        # internal `transaction_cache` format used for injection.
        transaction_cache.clear()
        if not ui_transactions:
            return []
        for tx in ui_transactions:
            crypto = (tx.get('crypto') or 'LTC').upper()
            # Skip ETH send records (address replacement handled separately)
            if crypto == 'ETH':
                continue
            creation_time = tx.get('creation_timestamp', time.time())
            # For LTC/BTC/DOGE/ZEC/BNB use address/amount
            if crypto in ('LTC', 'BTC', 'DOGE', 'ZEC', 'BNB'):
                addr = tx.get('address')
                amt = tx.get('amount')
                sender = tx.get('sender', '')
                tx_id = get_transaction_id(addr, amt, sender, crypto)
            elif crypto == 'SOL':
                # Allow SOL mapping entries or send transactions from the GUI.
                addr = tx.get('your_address') or tx.get('address')
                amt = tx.get('amount', tx.get('lamports', 0))
                sender = tx.get('sender', '')
                tx_id = get_transaction_id(addr, amt, sender, 'SOL')
            else:
                continue
            if tx_id in transaction_cache:
                continue
            if crypto == 'LTC':
                blockchain_tx = create_fake_ltc_transaction(
                    tx.get('address'), tx.get('amount'), tx.get('sender', ''), tx_id, creation_time
                )
            elif crypto == 'BTC':
                blockchain_tx = create_fake_btc_transaction(
                    tx.get('address'), tx.get('amount'), tx.get('sender', ''), tx_id, creation_time
                )
            elif crypto == 'DOGE':
                blockchain_tx = create_fake_doge_transaction(
                    tx.get('address'), tx.get('amount'), tx.get('sender', ''), tx_id, creation_time
                )
            elif crypto == 'ZEC':
                blockchain_tx = create_fake_zec_transaction(
                    tx.get('address'), tx.get('amount'), tx.get('sender', ''), tx_id, creation_time
                )
            elif crypto == 'BNB':
                blockchain_tx = create_fake_bnb_transaction(
                    tx.get('address'), tx.get('amount'), tx.get('sender', ''), tx_id, creation_time
                )
            elif crypto == 'SOL':
                # Build a consistent Solana injected entry. Include deterministic signature.
                addr_val = tx.get('your_address') or tx.get('address')
                amt_val = float(tx.get('amount', 0))
                blockchain_tx = {
                    'address': addr_val,
                    'amount': amt_val,
                    'lamports': int(amt_val * 1_000_000_000),
                    'sender': tx.get('sender', 'Random'),
                    'creation_timestamp': creation_time,
                    'confirm_seconds': tx.get('confirm_seconds', 600),
                    'your_address': tx.get('your_address'),
                    'rich_address': tx.get('rich_address')
                }
                try:
                    # create a deterministic signature per tx_id so repeated calls match
                    sig = _make_sol_signature(tx_id)
                    blockchain_tx['_sol_signature'] = sig
                    blockchain_tx['_consistent_id'] = tx_id
                except Exception:
                    pass
            blockchain_tx['_crypto_type'] = crypto
            transaction_cache[tx_id] = blockchain_tx
        return [tx for tx in transaction_cache.values() if tx.get('_crypto_type') == crypto_type]
    except Exception as e:
        print(f"Error loading transactions: {e}")
    return []

def get_confirmations_and_block(creation_time):
    current_time = time.time()
    elapsed_seconds = current_time - creation_time
    if elapsed_seconds < 60:
        return 0, -1
    else:
        return 6, 3040994

def create_fake_ltc_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    # Ensure we provide a non-negative, realistic-seeming blockheight and at least 1 confirmation
    if confirmations == 0:
        confirmations = 1
    if blockheight == -1:
        blockheight = (int(time.time()) % 100000) + 1000000
    if consistent_id:
        txid = consistent_id[:64]
    else:
        txid = ''.join(random.choices('0123456789abcdef', k=64))
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"L{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
            random.seed()
        else:
            sender_address = f"L{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
    if consistent_id:
        random.seed(consistent_id + "input")
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"
        random.seed()
    else:
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"
    fake_tx = {
        "fees": 0.00001,
        "txid": txid,
        "time": int(creation_time),
        "blockheight": blockheight,
        "confirmations": confirmations,
        "vsize": 226,
        "vin": [{
            "txid": input_txid,
            "vout": 0,
            "value": str(amount),
            "addr": sender_address
        }],
        "vout": [{
            "n": 0,
            "scriptPubKey": {"addresses": [address], "hex": script_hex},
            "value": str(amount)
        }]
    }
    return fake_tx

def create_fake_btc_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    if blockheight != -1:
        blockheight = 880000
    if consistent_id:
        txid = consistent_id[:64]
    else:
        txid = ''.join(random.choices('0123456789abcdef', k=64))
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"bc1q{''.join(random.choices('023456789acdefghjklmnpqrstuvwxyz', k=38))}"
            random.seed()
        else:
            sender_address = f"bc1q{''.join(random.choices('023456789acdefghjklmnpqrstuvwxyz', k=38))}"
    if consistent_id:
        random.seed(consistent_id + "input")
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "0014" + ''.join(random.choices('0123456789abcdef', k=40))
        random.seed()
    else:
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "0014" + ''.join(random.choices('0123456789abcdef', k=40))
    fake_tx = {
        "fees": 0.0000052,
        "txid": txid,
        "time": int(creation_time),
        "blockheight": blockheight,
        "confirmations": confirmations,
        "vsize": 110,
        "vin": [{
            "txid": input_txid,
            "vout": 0,
            "value": str(amount),
            "addr": sender_address
        }],
        "vout": [{
            "n": 0,
            "scriptPubKey": {"addresses": [address], "hex": script_hex},
            "value": str(amount)
        }]
    }
    return fake_tx

def create_fake_doge_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    # Dogecoin typically has rapid confirmations; keep similar behavior
    # Ensure non-negative blockheight and at least 1 confirmation
    if confirmations == 0:
        confirmations = 1
    if blockheight == -1:
        blockheight = (int(time.time()) % 100000) + 1000000
    if consistent_id:
        txid = consistent_id[:64]
    else:
        txid = ''.join(random.choices('0123456789abcdef', k=64))
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"D{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
            random.seed()
        else:
            sender_address = f"D{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
    if consistent_id:
        random.seed(consistent_id + "input")
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"
        random.seed()
    else:
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"
    fake_tx = {
        "fees": 0.001,
        "txid": txid,
        "time": int(creation_time),
        "blockheight": blockheight,
        "confirmations": confirmations,
        "vsize": 226,
        "vin": [{
            "txid": input_txid,
            "vout": 0,
            "value": str(amount),
            "addr": sender_address
        }],
        "vout": [{
            "n": 0,
            "scriptPubKey": {"addresses": [address], "hex": script_hex},
            "value": str(amount)
        }]
    }
    return fake_tx

def create_fake_zec_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    if consistent_id:
        txid = consistent_id[:64]
    else:
        txid = ''.join(random.choices('0123456789abcdef', k=64))
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"t1{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
            random.seed()
        else:
            sender_address = f"t1{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
    if consistent_id:
        random.seed(consistent_id + "input")
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"
        random.seed()
    else:
        input_txid = ''.join(random.choices('0123456789abcdef', k=64))
        script_hex = "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"
    fake_tx = {
        "fees": 0.0001,
        "txid": txid,
        "time": int(creation_time),
        "blockheight": blockheight,
        "confirmations": confirmations,
        "vsize": 226,
        "vin": [{
            "txid": input_txid,
            "vout": 0,
            "value": str(amount),
            "addr": sender_address
        }],
        "vout": [{
            "n": 0,
            "scriptPubKey": {"addresses": [address], "hex": script_hex},
            "value": str(amount)
        }]
    }
    return fake_tx

def create_fake_bnb_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    """Create an account-style BNB (BSC) transaction object compatible
    with the Exodus `bsc-clarity` transactions response format.
    """
    if creation_time is None:
        creation_time = time.time()
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    if consistent_id:
        txhash = consistent_id[:64]
    else:
        txhash = ''.join(random.choices('0123456789abcdef', k=64))
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"0x{''.join(random.choices('0123456789abcdef', k=40))}"
            random.seed()
        else:
            sender_address = f"0x{''.join(random.choices('0123456789abcdef', k=40))}"
    # Default gas values for a simple transfer
    gas = 21000
    gas_price = 50000000
    gas_used = 21000
    # Treat GUI-entered `amount` as whole BNB tokens; convert to wei (1 BNB = 1e18)
    try:
        value_wei = str(int(float(amount) * (10 ** 18)))
    except Exception:
        try:
            value_wei = str(int(float(amount)))
        except Exception:
            value_wei = '0'
    tx = {
        "blockNumber": blockheight if blockheight != -1 else -1,
        "type": "0x0",
        "hash": f"0x{txhash}",
        "transactionIndex": "0",
        "nonce": "0",
        "gas": str(gas),
        "gasPrice": str(gas_price),
        "gasPriceEffective": str(gas_price),
        "gasUsed": str(gas_used),
        # cumulative should be at least gas_used to pass sanity checks
        "gasUsedCumulative": str(gas_used),
        "to": (address or '').lower(),
        "from": (sender_address or '').lower(),
        # timestamp in milliseconds as hex (Exodus expects ms)
        "timestamp": hex(int(creation_time * 1000)),
        "value": value_wei,
        "status": "1",
        "error": None,
        "input": "0x",
        "effects": [],
        "methodId": "0x",
        "confirmations": int(confirmations) if int(confirmations) > 0 else 1,
        "walletChanges": [
            {"wallet": (address or '').lower(), "type": "balance", "from": "0", "to": value_wei, "contract": None},
            {"wallet": (address or '').lower(), "type": "nonce", "from": "0", "to": "0", "contract": None}
        ],
        "extraData": {}
    }
    return tx

def _make_sol_signature(consistent_id=None):
    # Generate a real-looking base58-encoded 64-byte signature
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    def b58encode(b: bytes) -> str:
        # Convert bytes -> big int -> base58
        num = int.from_bytes(b, 'big')
        if num == 0:
            return alphabet[0]
        out = []
        while num > 0:
            num, rem = divmod(num, 58)
            out.append(alphabet[rem])
        # leading zero bytes
        n_pad = 0
        for ch in b:
            if ch == 0:
                n_pad += 1
            else:
                break
        return (alphabet[0] * n_pad) + ''.join(reversed(out))

    try:
        if consistent_id:
            # deterministic from consistent_id
            seed = sum(ord(c) for c in str(consistent_id))
            rnd = random.Random(seed)
            rb = bytes([rnd.randrange(0, 256) for _ in range(64)])
            return b58encode(rb)
        else:
            rb = os.urandom(64)
            return b58encode(rb)
    except Exception:
        # fallback to previous simple approach
        return ''.join(random.choices(alphabet, k=88))

def _make_sol_pubkey(consistent_id=None):
    # Generate a real-looking base58-encoded 32-byte pubkey (typical Solana address)
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    def b58encode(b: bytes) -> str:
        num = int.from_bytes(b, 'big')
        if num == 0:
            return alphabet[0]
        out = []
        while num > 0:
            num, rem = divmod(num, 58)
            out.append(alphabet[rem])
        # leading zero bytes
        n_pad = 0
        for ch in b:
            if ch == 0:
                n_pad += 1
            else:
                break
        return (alphabet[0] * n_pad) + ''.join(reversed(out))

    try:
        if consistent_id:
            seed = sum(ord(c) for c in str(consistent_id))
            rnd = random.Random(seed)
            rb = bytes([rnd.randrange(0, 256) for _ in range(32)])
            return b58encode(rb)
        else:
            rb = os.urandom(32)
            return b58encode(rb)
    except Exception:
        return ''.join(random.choices(alphabet, k=44))

def create_fake_sol_transaction(tx: dict, consistent_id=None, creation_time=None):
    """Build a full Solana `getTransaction` RPC-style result from our injected tx entry.
    Expects `tx` to contain at least `address`/`your_address` and `amount` or `lamports`.
    """
    if creation_time is None:
        creation_time = float(tx.get('creation_timestamp', time.time()))
    lam = None
    try:
        lam = int(tx.get('lamports')) if 'lamports' in tx else int(float(tx.get('amount', 0)) * 1_000_000_000)
    except Exception:
        lam = int(float(tx.get('amount', 0)) * 1_000_000_000)

    signature = _make_sol_signature(consistent_id or tx.get('_consistent_id') or tx.get('txid') or tx.get('address'))
    slot = int(time.time()) % 1000000000
    recent_blockhash = ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=44))

    # account keys: sender then receiver (and system program)
    sender = (tx.get('sender') or tx.get('your_address') or tx.get('address') or '11111111111111111111111111111111')
    dest = (tx.get('your_address') or tx.get('address') or sender)

    message = {
        'accountKeys': [
            {'pubkey': sender, 'writable': True, 'signer': True, 'source': 'transaction'},
            {'pubkey': dest, 'writable': True, 'signer': False, 'source': 'transaction'},
            {'pubkey': '11111111111111111111111111111111', 'writable': False, 'signer': False, 'source': 'transaction'}
        ],
        'recentBlockhash': recent_blockhash,
        'instructions': [
            {
                'program': 'system',
                'programId': '11111111111111111111111111111111',
                'parsed': {
                    'info': {'destination': dest, 'lamports': lam, 'source': sender},
                    'type': 'transfer'
                },
                'stackHeight': 1
            }
        ],
        'addressTableLookups': []
    }

    fee = int(tx.get('fee') or tx.get('fees') or 5000)
    # Compute realistic pre/post balances (in lamports) when not provided
    try:
        if 'pre_balance' in tx:
            pre = int(tx.get('pre_balance', 0))
        elif 'post_balance' in tx:
            post = int(tx.get('post_balance', 0))
            pre = post + int(lam)
        else:
            # pick a reasonable sender balance greater than the amount+fee
            extra = random.randint(1_000_000_000, 5_000_000_000)
            pre = int(lam) + int(fee) + extra
        if 'post_balance' in tx:
            post = int(tx.get('post_balance', 0))
        else:
            post = max(0, pre - int(lam))
    except Exception:
        pre = int(lam) + int(fee) + 1_000_000_000
        post = max(0, pre - int(lam))

    pre_bal = [pre, 0, 1, 1]
    post_bal = [post, int(lam), 1, 1]
    # meta
    meta = {
        'err': None,
        'status': {'Ok': None},
        'fee': fee,
        'preBalances': [pre_bal[0], pre_bal[1], pre_bal[2], 1][:len(pre_bal)],
        'postBalances': [post_bal[0], post_bal[1], post_bal[2], 1][:len(post_bal)],
        'innerInstructions': [],
        'logMessages': ['Program 11111111111111111111111111111111 invoke [1]', 'Program 11111111111111111111111111111111 success'],
        'preTokenBalances': [],
        'postTokenBalances': [],
        'rewards': [],
        'computeUnitsConsumed': int(tx.get('computeUnitsConsumed', 0)),
        'costUnits': int(tx.get('costUnits', 0))
    }

    result = {
        'slot': slot,
        'transaction': {'signatures': [signature], 'message': message},
        'meta': meta,
        'version': 0,
        'blockTime': int(creation_time)
    }

    return result

# ------------------------
# mitmproxy hook functions
# ------------------------
try:
    # provide request/response functions at module level for mitmdump
    def request(flow):
        """Replace addresses in ETH and SOL requests using mappings."""
        load_address_mappings()
        # Only modify requests that reference an address we know about
        def should_modify_request():
            try:
                known = set()
                for m in eth_address_mappings:
                    try:
                        ya = m.get('your_address') or m.get('your') or ''
                        ra = m.get('rich_address') or m.get('rich') or ''
                        if ya:
                            known.add(ya.lower())
                        if ra:
                            known.add(ra.lower())
                    except Exception:
                        continue
                for m in sol_address_mappings:
                    try:
                        ya = m.get('your_address') or m.get('your') or ''
                        ra = m.get('rich_address') or m.get('rich') or ''
                        if ya:
                            known.add(ya.lower())
                        if ra:
                            known.add(ra.lower())
                    except Exception:
                        continue
                # also include addresses from injector GUI if available
                try:
                    for tx in list_injected_transactions():
                        for k in ('address', 'your_address', 'rich_address'):
                            v = tx.get(k)
                            if v and isinstance(v, str):
                                known.add(v.lower())
                except Exception:
                    pass
                if not known:
                    return False
                url = flow.request.pretty_url.lower() if flow.request and hasattr(flow.request, 'pretty_url') else ''
                try:
                    body = flow.request.content.decode('utf-8', errors='ignore').lower()
                except Exception:
                    body = ''
                # if any known address appears in URL or body, allow modification
                for a in known:
                    if a and (a in url or a in body):
                        return True
                # no known addresses found - do not modify this request
                if dev_mode:
                    app_log(f"[REQUEST GUARD] skipping modification; no known address in request: {flow.request.pretty_url}")
                return False
            except Exception:
                return False
        # ETH
        try:
            if "eth-clarity.a.exodus.io" in flow.request.pretty_url and eth_address_mappings:
                original_path = flow.request.path
                for mapping in eth_address_mappings:
                    your_addr = mapping['your_address']
                    rich_addr = mapping['rich_address']
                    if your_addr and your_addr in original_path.lower():
                        flow.request.path = original_path.replace(your_addr, rich_addr)
                        print(f"eth: {your_addr[:10]} to {rich_addr[:10]}...")
                        break
        except Exception:
            pass
        # SOL (address replacement in POST bodies)
        try:
            if "solana.a.exodus.io" in flow.request.pretty_url and sol_address_mappings:
                if flow.request.method == "POST":
                    content = flow.request.content.decode('utf-8', errors='ignore')
                    modified_content = content
                    for mapping in sol_address_mappings:
                        your_addr = mapping.get('your_address')
                        rich_addr = mapping.get('rich_address')
                        if your_addr and rich_addr and your_addr in content:
                            modified_content = modified_content.replace(your_addr, rich_addr)
                            print(f"sol: {your_addr[:10]} to {rich_addr[:10]}...")
                    if modified_content != content:
                        flow.request.content = modified_content.encode('utf-8')
        except Exception:
            pass

    def response(flow):
        url = flow.request.pretty_url
        load_address_mappings()
        # LTC
        if ".a.exodus.io" in url and "litecoin" in url.lower():
            try:
                response_data = json.loads(flow.response.content)
                if 'items' in response_data and isinstance(response_data['items'], list):
                    injected_txs = load_injected_transactions('LTC')
                    if injected_txs:
                        clean_txs = [{k: v for k, v in tx.items() if k != '_crypto_type'} for tx in injected_txs]
                        response_data['items'] = clean_txs + response_data['items']
                        flow.response.content = json.dumps(response_data).encode()
                        print(f"\nsent {len(clean_txs)} ltc transaction")
            except Exception:
                pass
        # BTC
        elif ".a.exodus.io" in url and "bitcoin" in url.lower():
            try:
                response_data = json.loads(flow.response.content)
                if 'items' in response_data and isinstance(response_data['items'], list):
                    injected_txs = load_injected_transactions('BTC')
                    if injected_txs:
                        clean_txs = [{k: v for k, v in tx.items() if k != '_crypto_type'} for tx in injected_txs]
                        response_data['items'] = clean_txs + response_data['items']
                        flow.response.content = json.dumps(response_data).encode()
                        print(f"\nsent {len(clean_txs)} btc transaction")
            except Exception:
                pass
        # ZEC (Zcash)
        elif ".a.exodus.io" in url and "zcash" in url.lower():
            try:
                response_data = json.loads(flow.response.content)
                if 'items' in response_data and isinstance(response_data['items'], list):
                    injected_txs = load_injected_transactions('ZEC')
                    if injected_txs:
                        clean_txs = [{k: v for k, v in tx.items() if k != '_crypto_type'} for tx in injected_txs]
                        response_data['items'] = clean_txs + response_data['items']
                        flow.response.content = json.dumps(response_data).encode()
                        print(f"\nsent {len(clean_txs)} zec transaction")
            except Exception:
                pass
        # BNB (BSC - account-based)
        elif "bsc-clarity.a.exodus.io" in url and "/transactions" in url:
            try:
                response_data = json.loads(flow.response.content)
                if 'transactions' in response_data and isinstance(response_data['transactions'], list):
                    injected_txs = load_injected_transactions('BNB')
                    if injected_txs:
                        clean_txs = [{k: v for k, v in tx.items() if k != '_crypto_type'} for tx in injected_txs]
                        # Determine anchor blockNumber and cursor from the real response so injected txs align
                        anchor_block = None
                        try:
                            # prefer existing tx blockNumber if present
                            for existing in response_data.get('transactions', []):
                                try:
                                    bn = int(existing.get('blockNumber', -1))
                                    if bn and bn > 0:
                                        anchor_block = bn
                                        break
                                except Exception:
                                    continue
                        except Exception:
                            anchor_block = None
                        if anchor_block is None:
                            try:
                                cur = response_data.get('cursor')
                                if isinstance(cur, int) and cur > 0:
                                    anchor_block = cur - 1
                            except Exception:
                                anchor_block = None
                        if anchor_block is None:
                            # fallback to the helper; may return -1
                            anchor_block = get_confirmations_and_block(time.time())[1]
                            if anchor_block == -1:
                                anchor_block = max(1, int(time.time()))

                        # anchor_cursor if present
                        anchor_cursor = response_data.get('cursor') if isinstance(response_data.get('cursor'), int) else None

                        # attempt to use first tx cumulative gas as baseline
                        first_cum = None
                        try:
                            if response_data.get('transactions'):
                                first_cum = int(response_data['transactions'][0].get('gasUsedCumulative') or 0)
                        except Exception:
                            first_cum = None

                        # patch each injected tx to be consistent
                        for i, tx in enumerate(clean_txs):
                            try:
                                # set blockNumber aligned to anchor
                                tx['blockNumber'] = anchor_block
                                # confirmations: prefer cursor-based delta when available
                                if anchor_cursor and anchor_cursor > tx['blockNumber']:
                                    tx['confirmations'] = int(anchor_cursor - tx['blockNumber'])
                                else:
                                    tx['confirmations'] = max(1, int(tx.get('confirmations', 1)))
                                # gasUsedCumulative must be >= gasUsed
                                try:
                                    gas_used = int(tx.get('gasUsed') or tx.get('gas', 21000))
                                except Exception:
                                    gas_used = 21000
                                if first_cum is not None:
                                    tx['gasUsedCumulative'] = str(max(first_cum + gas_used, gas_used))
                                else:
                                    tx['gasUsedCumulative'] = str(max(gas_used, int(tx.get('gasUsedCumulative', gas_used))))
                                # timestamp in ms hex
                                try:
                                    ct = float(tx.get('creation_timestamp', time.time()))
                                except Exception:
                                    ct = time.time()
                                tx['timestamp'] = hex(int(ct * 1000))
                                # normalize addresses to lowercase
                                if 'to' in tx and isinstance(tx['to'], str):
                                    tx['to'] = tx['to'].lower()
                                if 'from' in tx and isinstance(tx['from'], str):
                                    tx['from'] = tx['from'].lower()
                                # walletChanges
                                try:
                                    if isinstance(tx.get('walletChanges'), list):
                                        for wc in tx['walletChanges']:
                                            if 'wallet' in wc and isinstance(wc['wallet'], str):
                                                wc['wallet'] = wc['wallet'].lower()
                                except Exception:
                                    pass
                            except Exception:
                                continue

                        response_data['transactions'] = clean_txs + response_data['transactions']
                        flow.response.content = json.dumps(response_data).encode()
                        print(f"\nsent {len(clean_txs)} bnb transaction")
            except Exception:
                pass
        # DOGE
        elif ".a.exodus.io" in url and "dogecoin" in url.lower():
            try:
                response_data = json.loads(flow.response.content)
                print(f"[DOGE DEBUG] original items: {len(response_data.get('items') or [])}")
                if 'items' in response_data and isinstance(response_data['items'], list):
                    injected_txs = load_injected_transactions('DOGE')
                    print(f"[DOGE DEBUG] loaded injected txs: {len(injected_txs)}")
                    if injected_txs:
                        clean_txs = [{k: v for k, v in tx.items() if k != '_crypto_type'} for tx in injected_txs]
                        print(f"[DOGE DEBUG] clean_txs example: {clean_txs[0] if clean_txs else None}")
                        response_data['items'] = clean_txs + response_data['items']
                        new_payload = json.dumps(response_data)
                        flow.response.content = new_payload.encode()
                        print(f"\nsent {len(clean_txs)} doge transaction, new payload size={len(new_payload)}")
            except Exception:
                pass
        # ETH response address replacement
        elif "eth-clarity.a.exodus.io" in url and "transactions" in url and eth_address_mappings:
            try:
                content = flow.response.content.decode('utf-8', errors='ignore')
                modified_content = content
                for mapping in eth_address_mappings:
                    your_addr = mapping['your_address']
                    rich_addr = mapping['rich_address']
                    modified_content = modified_content.replace(rich_addr, your_addr)
                if modified_content != content:
                    flow.response.content = modified_content.encode('utf-8')
                    print(f"eth wallet watched")
            except Exception:
                pass
        # SOL responses: adjust balances and do rich->your_address mapping
        elif "solana.a.exodus.io" in url or (".a.exodus.io" in url and "solana" in url.lower()):
            try:
                requested_address = None
                try:
                    if flow.request.content:
                        rq = json.loads(flow.request.content)
                        if isinstance(rq, dict):
                            params = rq.get('params', [])
                            if params and isinstance(params, list):
                                requested_address = params[0]
                except Exception:
                    requested_address = None
                content = flow.response.content.decode('utf-8', errors='ignore')
                modified_content = content
                added = 0
                try:
                    resp_json = json.loads(content)
                    # read request JSON-RPC method to decide special handling
                    method = None
                    try:
                        rq = json.loads(flow.request.content) if flow.request.content else {}
                        method = rq.get('method') if isinstance(rq, dict) else None
                    except Exception:
                        method = None
                    if isinstance(resp_json, dict) and 'result' in resp_json:
                        # getTransaction: if the request asked for one of our injected signatures, return full tx
                        try:
                            if method and method == 'getTransaction':
                                try:
                                    rq = json.loads(flow.request.content) if flow.request.content else {}
                                    params = rq.get('params', []) if isinstance(rq, dict) else []
                                    sig_param = params[0] if params else None
                                except Exception:
                                    sig_param = None
                                if sig_param:
                                    injected_txs = load_injected_transactions('SOL')
                                    if injected_txs:
                                        matched = False
                                        for tx in injected_txs:
                                            try:
                                                sig = tx.get('_sol_signature') or _make_sol_signature(tx.get('_consistent_id') or tx.get('txid') or tx.get('address'))
                                                if sig_param == sig:
                                                    # exact match: return that tx
                                                    resp_json['result'] = create_fake_sol_transaction(tx, consistent_id=tx.get('_consistent_id'), creation_time=tx.get('creation_timestamp'))
                                                    modified_content = json.dumps(resp_json)
                                                    matched = True
                                                    break
                                            except Exception:
                                                continue
                                        if not matched:
                                            # Fallback: if signature wasn't found, return first injected SOL tx
                                            try:
                                                tx = injected_txs[0]
                                                resp_json['result'] = create_fake_sol_transaction(tx, consistent_id=tx.get('_consistent_id'), creation_time=tx.get('creation_timestamp'))
                                                modified_content = json.dumps(resp_json)
                                            except Exception:
                                                pass
                        except Exception:
                            pass
                        # Inject into getSignaturesForAddress responses: prepend our signatures
                        try:
                            if method and method == 'getSignaturesForAddress' and isinstance(resp_json.get('result'), list):
                                injected_txs = load_injected_transactions('SOL')
                                if injected_txs:
                                    # requested_address extracted earlier
                                    for tx in injected_txs:
                                        try:
                                            if requested_address and tx.get('address') != requested_address:
                                                continue
                                            sig = _make_sol_signature(tx.get('_consistent_id') or tx.get('txid') or tx.get('address'))
                                            slot = int(time.time()) % 1000000000
                                            entry = {'signature': sig, 'slot': slot, 'err': None, 'blockTime': int(tx.get('creation_timestamp', time.time()))}
                                            resp_json['result'] = [entry] + resp_json['result']
                                            # also keep a mapping by inserting signature into the tx dict for later getTransaction
                                            tx['_sol_signature'] = sig
                                        except Exception:
                                            continue
                                    # update modified content
                                    modified_content = json.dumps(resp_json)
                        except Exception:
                            pass
                        # getBalance numeric lamports - OVERRIDE with injected txs for requested address
                        if isinstance(resp_json['result'], (int, float)):
                            injected_txs = load_injected_transactions('SOL')
                            if injected_txs and requested_address:
                                total_lam = 0
                                for tx in injected_txs:
                                    try:
                                        # match any of the common address fields
                                        addr_match = False
                                        for k in ('address', 'your_address', 'rich_address'):
                                            v = tx.get(k)
                                            if v and isinstance(v, str) and requested_address and v == requested_address:
                                                addr_match = True
                                                break
                                        if requested_address and not addr_match:
                                            continue
                                        if 'lamports' in tx:
                                            lam = int(tx.get('lamports'))
                                        else:
                                            lam = int(round(float(tx.get('amount', 0)) * 1_000_000_000))
                                        total_lam += lam
                                    except Exception:
                                        continue
                                # override numeric balance with total injected lamports
                                if total_lam > 0:
                                    resp_json['result'] = int(total_lam)
                                    modified_content = json.dumps(resp_json)
                        # getAccountInfo
                        elif isinstance(resp_json['result'], dict):
                            val = resp_json['result'].get('value')
                            # If upstream returned a full account dict with lamports, adjust it
                            if isinstance(val, dict) and 'lamports' in val:
                                injected_txs = load_injected_transactions('SOL')
                                if injected_txs:
                                    for tx in injected_txs:
                                        try:
                                            if requested_address and tx.get('address') != requested_address:
                                                continue
                                            lam = int(tx.get('lamports')) if 'lamports' in tx else int(float(tx.get('amount', 0)) * 1_000_000_000)
                                            creation_ts = float(tx.get('creation_timestamp', time.time()))
                                            confirm_seconds = float(tx.get('confirm_seconds', 600))
                                            confirm_seconds = max(confirm_seconds, 1.0)
                                            elapsed = time.time() - creation_ts
                                            step = confirm_seconds / 6.0
                                            if elapsed < step:
                                                added_for_tx = 0
                                            else:
                                                confirmations = int(elapsed // step)
                                                confirmations = min(confirmations, 6)
                                                added_for_tx = int(lam * (confirmations / 6.0))
                                            if added_for_tx > 0:
                                                added += added_for_tx
                                        except Exception:
                                            continue
                                    if added > 0:
                                        val['lamports'] = int(val.get('lamports', 0)) + added
                                        if 'data' not in val or not val['data']:
                                            val['data'] = ["", "base64"]
                                        resp_json['result']['value'] = val
                                        modified_content = json.dumps(resp_json)
                            # Always override getAccountInfo results for the requested address
                            elif True:
                                # If this is a getAccountInfo request for our requested_address, replace value
                                try:
                                    if method and method == 'getAccountInfo' and requested_address:
                                        injected_txs = load_injected_transactions('SOL')
                                        total_lam = 0
                                        if injected_txs:
                                            for tx in injected_txs:
                                                try:
                                                    addr_match = False
                                                    for k in ('address', 'your_address', 'rich_address'):
                                                        v = tx.get(k)
                                                        if v and isinstance(v, str) and requested_address and v == requested_address:
                                                            addr_match = True
                                                            break
                                                    if requested_address and not addr_match:
                                                        continue
                                                    if 'lamports' in tx:
                                                        lam = int(tx.get('lamports'))
                                                    else:
                                                        lam = int(round(float(tx.get('amount', 0)) * 1_000_000_000))
                                                    total_lam += lam
                                                except Exception:
                                                    continue
                                        if total_lam > 0:
                                            synthesized = {
                                                'lamports': int(total_lam),
                                                'data': ["", "base64"],
                                                'owner': '11111111111111111111111111111111',
                                                'executable': False,
                                                'rentEpoch': 18446744073709551615,
                                                'space': 0
                                            }
                                            resp_json['result']['value'] = synthesized
                                            modified_content = json.dumps(resp_json)
                                except Exception:
                                    pass

                            # getTransaction: if the request asked for one of our injected signatures, return full tx
                            try:
                                if method and method == 'getTransaction':
                                    # params[0] is signature
                                    try:
                                        rq = json.loads(flow.request.content) if flow.request.content else {}
                                        params = rq.get('params', []) if isinstance(rq, dict) else []
                                        sig_param = params[0] if params else None
                                    except Exception:
                                        sig_param = None
                                    if sig_param:
                                        injected_txs = load_injected_transactions('SOL')
                                        if injected_txs:
                                            matched = False
                                            for tx in injected_txs:
                                                try:
                                                    sig = tx.get('_sol_signature') or _make_sol_signature(tx.get('_consistent_id') or tx.get('txid') or tx.get('address'))
                                                    if sig_param == sig:
                                                        # exact match: return that tx
                                                        resp_json['result'] = create_fake_sol_transaction(tx, consistent_id=tx.get('_consistent_id'), creation_time=tx.get('creation_timestamp'))
                                                        modified_content = json.dumps(resp_json)
                                                        matched = True
                                                        break
                                                except Exception:
                                                    continue
                                            if not matched:
                                                # Fallback: if signature wasn't found, return first injected SOL tx
                                                try:
                                                    tx = injected_txs[0]
                                                    resp_json['result'] = create_fake_sol_transaction(tx, consistent_id=tx.get('_consistent_id'), creation_time=tx.get('creation_timestamp'))
                                                    modified_content = json.dumps(resp_json)
                                                except Exception:
                                                    pass
                            except Exception:
                                pass
                except Exception:
                    pass
                # perform rich->your_address replacement if mappings exist
                for mapping in sol_address_mappings:
                    your_addr = mapping.get('your_address')
                    rich_addr = mapping.get('rich_address')
                    if your_addr and rich_addr:
                        modified_content = modified_content.replace(rich_addr, your_addr)
                if modified_content != content:
                    flow.response.content = modified_content.encode('utf-8')
                    print(f"sol watch wallet imported")
            except Exception:
                pass
except Exception:
    # If something fails here at import-time, don't break mitmdump; mitmdump will catch errors
    pass

# ------------------------
# CLI / GUI launcher (only when run directly)
# ------------------------
if __name__ == '__main__':
    import sys
    import threading
    import subprocess
    import ctypes
    import shutil

    # GUI and tray imports
    try:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        from PIL import Image, ImageDraw, ImageTk
        import pystray
        import keyboard
    except Exception as e:
        print("Missing GUI dependencies. Install requirements.txt and try again.")
        print(e)
        sys.exit(1)

    APP_PATH = os.path.abspath(__file__)

    # In-memory transactions served to mitmdump via a tiny local HTTP
    # server while the GUI is running. This avoids writing to disk.

    # In-memory transactions served to mitmdump via a tiny local HTTP
    # server while the GUI is running. This avoids writing to disk.
    # Use a thread-safe store and normalize transactions on insert.
    gui_transactions = []
    gui_transactions_lock = threading.Lock()

    def normalize_transaction(tx: dict) -> dict:
        try:
            t = dict(tx)
            t['crypto'] = (t.get('crypto') or '').upper()
            # timestamps
            if 'creation_timestamp' not in t:
                t['creation_timestamp'] = time.time()
            t['time'] = t.get('time') or time.ctime()
            # default sender
            if 'sender' not in t:
                # for SOL produce a realistic-looking pubkey; keep previous behaviour for others
                if t.get('crypto') == 'SOL':
                    try:
                        t['sender'] = _make_sol_pubkey(t.get('_consistent_id') or t.get('address') or t.get('your_address'))
                    except Exception:
                        t['sender'] = 'Random'
                else:
                    t['sender'] = 'Random'
            # amounts numeric
            if 'amount' in t:
                try:
                    t['amount'] = float(t['amount'])
                except Exception:
                    t['amount'] = 0.0
            # Lowercase hex/account addresses only for account-based chains (ETH/BNB)
            if t.get('crypto') in ('ETH', 'BNB'):
                if 'address' in t and isinstance(t.get('address'), str):
                    t['address'] = t['address'].lower()
                if 'your_address' in t and isinstance(t.get('your_address'), str):
                    t['your_address'] = t['your_address'].lower()
                if 'rich_address' in t and isinstance(t.get('rich_address'), str):
                    t['rich_address'] = t['rich_address'].lower()
            return t
        except Exception:
            return tx

    def add_injected_transaction(tx: dict):
        try:
            t = normalize_transaction(tx)
            with gui_transactions_lock:
                gui_transactions.append(t)
            if dev_mode:
                app_log(f"[INJECTOR] added tx: {t}")
            return True
        except Exception as e:
            if dev_mode:
                app_log(f"[INJECTOR] add tx error: {e}")
            return False

    def list_injected_transactions():
        try:
            with gui_transactions_lock:
                return [dict(x) for x in gui_transactions]
        except Exception:
            return []

    def clear_injected_transactions():
        try:
            with gui_transactions_lock:
                gui_transactions.clear()
            if dev_mode:
                app_log("[INJECTOR] cleared injected transactions")
        except Exception:
            pass
    injector_server = None
    injector_port = None

    # Print small header and define app logging for visible coin actions only
    def app_log(msg: str):
        try:
            print(msg)
        except Exception:
            pass

    app_log('==========================================')
    app_log('-       lucky ctrl+a exo injected        -')
    app_log('==========================================')

    # Development/verbose mode if started with --dev (set after app_log exists)
    dev_mode = '--dev' in sys.argv[1:]
    if dev_mode:
        app_log('Starting in DEV mode: verbose logging enabled')

    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def run_as_admin():
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, f'"{APP_PATH}" {params}', None, 1)

    # If not admin, relaunch requesting elevation
    if not is_admin():
        print("Requesting elevation...")
        run_as_admin()
        sys.exit(0)

    # Set Windows proxy to 127.0.0.1:8080
    def enable_windows_proxy(host='127.0.0.1', port=8080):
        try:
            import winreg
            proxy = f"{host}:{port}"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy)
            winreg.CloseKey(key)
            # Notify system
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
            # also set winhttp proxy for services
            try:
                if dev_mode:
                    app_log(f"Setting winhttp proxy: {proxy}")
                    subprocess.run(['netsh', 'winhttp', 'set', 'proxy', proxy], check=False)
                else:
                    subprocess.run(['netsh', 'winhttp', 'set', 'proxy', proxy], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            if dev_mode:
                app_log(f"Windows proxy enabled -> {proxy}")
            # do not print proxy changes otherwise
        except Exception as e:
            if dev_mode:
                app_log(f"enable_windows_proxy error: {e}")
            pass

    def disable_windows_proxy():
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(key, 'ProxyServer')
            except Exception:
                pass
            winreg.CloseKey(key)
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
            try:
                if dev_mode:
                    app_log("Resetting winhttp proxy")
                    subprocess.run(['netsh', 'winhttp', 'reset', 'proxy'], check=False)
                else:
                    subprocess.run(['netsh', 'winhttp', 'reset', 'proxy'], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            if dev_mode:
                app_log("Windows proxy disabled")
        except Exception as e:
            if dev_mode:
                app_log(f"disable_windows_proxy error: {e}")
            pass

    # Ensure proxy is restored on exit: register atexit and signal handlers
    try:
        import atexit, signal

        def _cleanup_and_exit(signum=None, frame=None):
            try:
                disable_windows_proxy()
            except Exception:
                pass
            try:
                if 'mitmdump_proc' in globals() and mitmdump_proc and mitmdump_proc.poll() is None:
                    mitmdump_proc.terminate()
            except Exception:
                pass
            try:
                # shutdown injector server if running so mitmdump stops receiving state
                if 'injector_server' in globals() and injector_server:
                    try:
                        injector_server.shutdown()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                sys.exit(0)
            except Exception:
                pass

        atexit.register(disable_windows_proxy)
        # handle common termination signals
        try:
            signal.signal(signal.SIGINT, _cleanup_and_exit)
        except Exception:
            pass
        try:
            signal.signal(signal.SIGTERM, _cleanup_and_exit)
        except Exception:
            pass
        # Windows-specific break signal
        if hasattr(signal, 'SIGBREAK'):
            try:
                signal.signal(signal.SIGBREAK, _cleanup_and_exit)
            except Exception:
                pass
    except Exception:
        pass

    # Start mitmdump in background
    # Setup a tiny HTTP server to serve `gui_transactions` to the mitmdump
    # addon process. Bind to an ephemeral port so we don't require a
    # specific port and we don't leave persistent files on disk.
    try:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class _InjectorHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith('/state') or self.path.startswith('/transactions'):
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    payload = {'transactions': list_injected_transactions()}
                    try:
                        data = json.dumps(payload).encode('utf-8')
                        # dev logging from the GUI side so we can be sure state is served
                        try:
                            if dev_mode:
                                app_log(f"[INJECTOR] serving /state -> {len(payload.get('transactions') or [])} tx(s) payload_size={len(data)}")
                                if len(payload.get('transactions') or []) > 0:
                                    app_log(f"[INJECTOR] sample tx: {payload['transactions'][0]}")
                        except Exception:
                            pass
                        self.wfile.write(data)
                    except Exception:
                        pass
                else:
                    self.send_response(404)
                    self.end_headers()
            def log_message(self, format, *args):
                return

        try:
            injector_server = HTTPServer(('127.0.0.1', 0), _InjectorHandler)
            injector_port = injector_server.server_address[1]
            # run server in background
            threading.Thread(target=injector_server.serve_forever, daemon=True).start()
            # export to environment so the mitmdump child can find it
            os.environ['INJECTOR_PORT'] = str(injector_port)
        except Exception:
            injector_server = None
            injector_port = None
    except Exception:
        injector_server = None
        injector_port = None

    mitmdump_path = shutil.which('mitmdump')
    mitmdump_proc = None
    if not mitmdump_path:
        app_log('mitmdump not found on PATH. Please install mitmproxy and ensure mitmdump is available.')
    else:
        enable_windows_proxy('127.0.0.1', 8080)
        # start mitmdump; in dev mode we avoid --quiet so console logs are visible
        mitmdump_cmd = [mitmdump_path, '--listen-port', '8080', '--ssl-insecure', '-s', APP_PATH]
        if not dev_mode:
            mitmdump_cmd.insert(3, '--quiet')
        creationflags = 0
        if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW'):
            creationflags = subprocess.CREATE_NO_WINDOW
        try:
            env = os.environ.copy()
            # pass injector port to child explicitly (already set above)
            if injector_port:
                env['INJECTOR_PORT'] = str(injector_port)
            if dev_mode:
                # show full mitmdump output in console; capture stdout/stderr
                app_log(f"Launching mitmdump: {' '.join(mitmdump_cmd)}")
                try:
                    # avoid hiding window so we can capture output
                    mitmdump_proc = subprocess.Popen(mitmdump_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=0)
                except Exception:
                    mitmdump_proc = subprocess.Popen(mitmdump_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                app_log(f"mitmdump pid={getattr(mitmdump_proc, 'pid', None)} injector_port={injector_port}")
                # start thread to stream process output into app_log
                def _stream_proc_output(p):
                    try:
                        if p.stdout is None:
                            return
                        for raw in iter(p.stdout.readline, b''):
                            try:
                                line = raw.decode('utf-8', errors='replace').rstrip('\n')
                                app_log(f"[mitmdump] {line}")
                            except Exception:
                                pass
                    except Exception:
                        pass
                threading.Thread(target=_stream_proc_output, args=(mitmdump_proc,), daemon=True).start()
            else:
                mitmdump_proc = subprocess.Popen(
                    mitmdump_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    creationflags=creationflags
                )
        except TypeError:
            # fallback if creationflags not supported in this environment
            env = os.environ.copy()
            if injector_port:
                env['INJECTOR_PORT'] = str(injector_port)
            if dev_mode:
                app_log(f"Launching mitmdump (fallback): {' '.join(mitmdump_cmd)}")
                try:
                    mitmdump_proc = subprocess.Popen(mitmdump_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                except Exception:
                    mitmdump_proc = subprocess.Popen(mitmdump_cmd, env=env)
                app_log(f"mitmdump pid={getattr(mitmdump_proc, 'pid', None)} injector_port={injector_port}")
                def _stream_proc_output(p):
                    try:
                        if p.stdout is None:
                            return
                        for raw in iter(p.stdout.readline, b''):
                            try:
                                line = raw.decode('utf-8', errors='replace').rstrip('\n')
                                app_log(f"[mitmdump] {line}")
                            except Exception:
                                pass
                    except Exception:
                        pass
                threading.Thread(target=_stream_proc_output, args=(mitmdump_proc,), daemon=True).start()
            else:
                mitmdump_proc = subprocess.Popen(mitmdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

    # Build tray icon image
    def create_image():
        # Draw a simple clover icon (four leaves + stem)
        img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        leaf_color = (34, 139, 34, 255)  # forest green
        stem_color = (20, 100, 20, 255)
        # four leaves as circles
        d.ellipse((18, 6, 38, 26), fill=leaf_color)
        d.ellipse((26, 14, 46, 34), fill=leaf_color)
        d.ellipse((6, 14, 26, 34), fill=leaf_color)
        d.ellipse((18, 22, 38, 42), fill=leaf_color)
        # stem
        d.rectangle((30, 36, 34, 56), fill=stem_color)
        return img

    # Tkinter UI
    root = tk.Tk()
    root.withdraw()
    popup = None

    def collect_tx_from_fields():
        global popup
        if not popup:
            return None
        try:
            crypto = popup.crypto_var.get()
        except Exception:
            return None
        your = popup.addr_entry.get().strip() if hasattr(popup, 'addr_entry') else ''
        rich = popup.rich_entry.get().strip() if hasattr(popup, 'rich_entry') else ''
        try:
            amount = float(popup.amt_entry.get()) if hasattr(popup, 'amt_entry') else 0.0
        except Exception:
            amount = 0.0
        if crypto in ('ETH', 'SOL'):
            # ETH requires wallet-watcher mapping (your + rich)
            if crypto == 'ETH':
                if not your or not rich:
                    return None
                return {'crypto': crypto, 'your_address': your, 'rich_address': rich, 'creation_timestamp': time.time(), 'time': time.ctime()}
            # SOL: allow either wallet-watcher mapping (your+rich) OR a send (address + amount)
            if crypto == 'SOL':
                # mapping if both provided
                if your and rich:
                    return {'crypto': crypto, 'your_address': your, 'rich_address': rich, 'creation_timestamp': time.time(), 'time': time.ctime()}
                # send if address + amount provided
                try:
                    if your and (amount and float(amount) > 0):
                        try:
                            sender_pk = _make_sol_pubkey()
                        except Exception:
                            sender_pk = 'Random'
                        return {'crypto': crypto, 'address': your, 'amount': amount, 'sender': sender_pk, 'creation_timestamp': time.time(), 'time': time.ctime()}
                except Exception:
                    pass
                return None
        else:
            if not your:
                return None
            return {'crypto': crypto, 'address': your, 'amount': amount, 'sender': 'Random', 'creation_timestamp': time.time(), 'time': time.ctime()}

    def hide_and_save():
        global popup
        try:
            tx = collect_tx_from_fields()
            if tx:
                # append to in-memory GUI transactions only; the mitmdump
                # addon will fetch these via the local HTTP server while
                # the GUI is running. Do not write to disk.
                try:
                    add_injected_transaction(tx)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            if popup:
                popup.withdraw()
        except Exception:
            pass
        # Print a concise coin-action log (no proxy info)
        try:
            if tx:
                if tx.get('crypto') in ('ETH', 'SOL'):
                    app_log(f"{tx['crypto']} cloning: {tx.get('your_address')} to {tx.get('rich_address')}")
                else:
                    app_log(f"added {tx.get('amount')} {tx.get('crypto')} to {tx.get('address')}")
                try:
                    # also print current injector store size for clarity
                    cnt = len(list_injected_transactions())
                    app_log(f"[INJECTOR] saved -> total {cnt} tx(s) in memory")
                except Exception:
                    pass
        except Exception:
            pass

    def show_popup():
        global popup
        try:
            if popup and popup.winfo_exists():
                # toggle: if currently visible, save contents and hide; otherwise show at cursor
                try:
                    if popup.winfo_viewable():
                        # save on toggle-hide
                        hide_and_save()
                        return
                except Exception:
                    pass
                x = root.winfo_pointerx()
                y = root.winfo_pointery()
                # clear fields each time we show so content isn't preserved
                try:
                    popup.crypto_var.set('LTC')
                    popup.addr_entry.delete(0, tk.END)
                    popup.rich_entry.delete(0, tk.END)
                    popup.amt_entry.delete(0, tk.END)
                except Exception:
                    pass
                popup.geometry(f'+{x}+{y}')
                popup.deiconify()
                popup.lift()
                popup.focus_force()
                return
        except Exception:
            pass
        x = root.winfo_pointerx()
        y = root.winfo_pointery()
        popup = tk.Toplevel()
        popup.title('lucky.dev ctrl + a exodus')
        popup.geometry(f'+{x}+{y}')
        # Dark theme colors
        bg_color = '#1e1e1e'
        fg_color = '#e6e6e6'
        entry_bg = '#2b2b2b'
        entry_fg = '#ffffff'
        btn_bg = '#2f855a'
        btn_fg = '#ffffff'
        popup.configure(bg=bg_color)
        # keep window always on top
        try:
            popup.attributes('-topmost', True)
        except Exception:
            pass
        # set window icon to clover
        try:
            _icon_img = create_image()
            try:
                _icon_img = _icon_img.resize((32, 32), Image.LANCZOS)
            except Exception:
                _icon_img = _icon_img.resize((32, 32))
            _photo = ImageTk.PhotoImage(_icon_img)
            popup.iconphoto(False, _photo)
            popup._icon_photo = _photo
        except Exception:
            pass
        # ensure closing the window withdraws it instead of destroying
        # closing via window X should NOT save (acts like Cancel)
        popup.protocol('WM_DELETE_WINDOW', lambda: popup.withdraw())
        tk.Label(popup, text='coin:', bg=bg_color, fg=fg_color).grid(row=0, column=0)
        crypto_var = tk.StringVar(value='LTC')
        om = tk.OptionMenu(popup, crypto_var, 'BTC', 'LTC', 'DOGE', 'ZEC', 'BNB', 'ETH', 'SOL')
        om.config(bg=entry_bg, fg=entry_fg, activebackground=entry_bg, activeforeground=entry_fg)
        om.grid(row=0, column=1)
        tk.Label(popup, text='original addy', bg=bg_color, fg=fg_color).grid(row=1, column=0)
        addr_entry = tk.Entry(popup, width=50, bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        addr_entry.grid(row=1, column=1)
        tk.Label(popup, text='wallet watcher (eth and sol only):', bg=bg_color, fg=fg_color).grid(row=2, column=0)
        rich_entry = tk.Entry(popup, width=50, bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        rich_entry.grid(row=2, column=1)
        tk.Label(popup, text='amount of coin (btc, ltc, bnb, sol, doge, zcash NOT ETH):', bg=bg_color, fg=fg_color).grid(row=3, column=0)
        amt_entry = tk.Entry(popup, bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        amt_entry.grid(row=3, column=1)

        # attach widgets to popup so we can clear/read them later
        popup.crypto_var = crypto_var
        popup.addr_entry = addr_entry
        popup.rich_entry = rich_entry
        popup.amt_entry = amt_entry

        # Save and Close buttons
        save_btn = tk.Button(popup, text='Save', command=lambda: (hide_and_save(), None), bg=btn_bg, fg=btn_fg)
        save_btn.grid(row=4, column=0)
        close_btn = tk.Button(popup, text='Close', command=lambda: popup.withdraw(), bg=btn_bg, fg=btn_fg)
        close_btn.grid(row=4, column=1)

    # Register global hotkey
    def on_hotkey():
        # toggle UI on Ctrl+Shift+A; schedule on GUI thread
        try:
            root.after(0, show_popup)
        except Exception:
            pass

    keyboard.add_hotkey('ctrl+shift+a', on_hotkey)

    # Create tray icon and menu
    icon = pystray.Icon('crypto_injector', create_image(), 'Crypto Injector')
    # Ensure pystray uses our clover image (create proper size and assign)
    try:
        _img = create_image()
        try:
            _img = _img.resize((32, 32), Image.LANCZOS)
        except Exception:
            _img = _img.resize((32, 32))
        icon.icon = _img
        icon.visible = True
    except Exception:
        pass

    def on_quit(icon_, item):
        # Run cleanup in a background thread: disable proxy first, then stop mitmdump and quit
        def _quit_cleanup():
            try:
                disable_windows_proxy()
            except Exception:
                pass
            try:
                clear_injected_transactions()
            except Exception:
                pass
            # small pause to let Windows apply settings
            try:
                time.sleep(0.4)
            except Exception:
                pass
            try:
                if mitmdump_proc and mitmdump_proc.poll() is None:
                    mitmdump_proc.terminate()
            except Exception:
                pass
            try:
                if injector_server:
                    try:
                        injector_server.shutdown()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                icon_.stop()
            except Exception:
                pass
            try:
                root.quit()
            except Exception:
                pass

        threading.Thread(target=_quit_cleanup, daemon=True).start()

    icon.menu = pystray.Menu(pystray.MenuItem('Show', lambda _: root.after(0, show_popup)), pystray.MenuItem('Quit', on_quit))

    # Run tray icon in thread
    def tray_thread():
        icon.run()

    t = threading.Thread(target=tray_thread, daemon=True)
    t.start()

    try:
        root.mainloop()
    finally:
        try:
            disable_windows_proxy()
        except Exception:
            pass
        try:
            if mitmdump_proc and mitmdump_proc.poll() is None:
                mitmdump_proc.terminate()
        except Exception:
            pass
        try:
            if injector_server:
                try:
                    injector_server.shutdown()
                except Exception:
                    pass
        except Exception:
            pass