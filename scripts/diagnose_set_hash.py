#!/usr/bin/env python3
"""
Diagnostic script: check every condition that _isEligibleHashSetter validates
in KMSRegistry.setMasterSecretHash().

Usage:
    python scripts/diagnose_set_hash.py [TEE_WALLET_ADDRESS]
"""

import sys
from web3 import Web3
from eth_abi import decode

# ── Config ──────────────────────────────────────────────────────────────────
RPC_URL = "http://odyn.sparsity.cloud:8545"
KMS_REGISTRY = "0x934744f9D931eF72d7fa10b07CD46BCFA54e8d88"
NOVA_APP_REGISTRY = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
TEE_WALLET = sys.argv[1] if len(sys.argv) > 1 else "0xDa0573900931885acC310Eb10ec7B25B22b999F1"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
print(f"RPC connected: {w3.is_connected()}, block: {w3.eth.block_number}\n")

# ── Minimal ABIs ────────────────────────────────────────────────────────────
KMS_ABI = [
    {"inputs": [], "name": "kmsAppId", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "masterSecretHash", "outputs": [{"type": "bytes32"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "novaAppRegistry", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "owner", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"type": "address"}], "name": "isOperator", "outputs": [{"type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getOperators", "outputs": [{"type": "address[]"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "operatorCount", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
]

STATUS_NAMES = {0: "ACTIVE", 1: "STOPPED/SUSPENDED", 2: "FAILED/DEREGISTERED"}
VERSION_STATUS_NAMES = {0: "ENROLLED", 1: "DEPRECATED/SUSPENDED", 2: "REVOKED"}

# ── Contracts ───────────────────────────────────────────────────────────────
kms = w3.eth.contract(address=Web3.to_checksum_address(KMS_REGISTRY), abi=KMS_ABI)

# ── Manual eth_call helpers (raw ABI decoding to avoid struct issues) ──────
def function_selector(sig):
    return Web3.keccak(text=sig)[:4]

def eth_call_raw(to, data):
    result = w3.eth.call({"to": Web3.to_checksum_address(to), "data": data})
    return bytes(result)

def load_word(data, index):
    offset = index * 32
    return int.from_bytes(data[offset:offset+32], "big")

def load_address(data, index):
    return Web3.to_checksum_address("0x" + data[index*32+12 : index*32+32].hex())

# ── Check 1: KMSRegistry basic state ───────────────────────────────────────
print("=" * 70)
print("CHECK 1: KMSRegistry basic state")
print("=" * 70)

kms_app_id = kms.functions.kmsAppId().call()
master_hash = kms.functions.masterSecretHash().call()
on_chain_registry = kms.functions.novaAppRegistry().call()
operator_count = kms.functions.operatorCount().call()

hash_is_zero = (master_hash == b'\x00' * 32)
print(f"  kmsAppId:           {kms_app_id}  {'✅' if kms_app_id > 0 else '❌ ZERO — setKmsAppId() not called!'}")
print(f"  masterSecretHash:   0x{master_hash.hex()}  {'(ZERO — can be set) ✅' if hash_is_zero else '(ALREADY SET — cannot set again!) ❌'}")
print(f"  novaAppRegistry:    {on_chain_registry}  {'✅ matches' if on_chain_registry.lower() == NOVA_APP_REGISTRY.lower() else '❌ MISMATCH! Expected ' + NOVA_APP_REGISTRY}")
print(f"  operatorCount:      {operator_count}")

if operator_count > 0:
    try:
        operators = kms.functions.getOperators().call()
        for i, op in enumerate(operators):
            print(f"    operator[{i}]: {op}")
    except Exception as e:
        print(f"    (failed to list operators: {e})")

is_op = kms.functions.isOperator(Web3.to_checksum_address(TEE_WALLET)).call()
print(f"  isOperator({TEE_WALLET}): {is_op}")

# ── Check 2: NovaAppRegistry — getInstanceByWallet (raw decoding) ──────────
print()
print("=" * 70)
print(f"CHECK 2: NovaAppRegistry.getInstanceByWallet({TEE_WALLET})")
print("=" * 70)

# Encode: getInstanceByWallet(address)
selector = function_selector("getInstanceByWallet(address)")
encoded_addr = bytes.fromhex(TEE_WALLET[2:].lower().zfill(64))
calldata = selector + encoded_addr

try:
    raw = eth_call_raw(NOVA_APP_REGISTRY, calldata)
    
    if len(raw) < 32 * 10:
        print(f"  ❌ Return data too short ({len(raw)} bytes)")
    else:
        # The contract returns:
        #   (uint256 id, uint256 appId, uint256 versionId, address operator,
        #    string instanceUrl, bytes teePubkey, address teeWalletAddress,
        #    bool zkVerified, uint8 status, uint256 registeredAt)
        # For head words (non-dynamic types or offsets):
        #   word[0] = id (or offset if struct wrapper)
        #   ... 
        # The contract may wrap everything in a tuple with a head offset.
        # Let's detect: if word[0] is 0x20 (=32), it's a struct offset wrapper.
        
        word0 = load_word(raw, 0)
        
        if word0 == 32:
            # Struct-wrapped: actual data starts at offset 32
            data = raw[32:]
            print(f"  (struct-wrapped return data, unwrapping...)")
        else:
            data = raw
        
        # Now decode the 10 head words:
        # word[0] = id
        # word[1] = appId
        # word[2] = versionId
        # word[3] = operator (address, right-aligned in 32 bytes)
        # word[4] = offset to instanceUrl
        # word[5] = offset to teePubkey
        # word[6] = teeWalletAddress (address)
        # word[7] = zkVerified (bool)
        # word[8] = status (uint8)
        # word[9] = registeredAt

        inst_id = load_word(data, 0)
        app_id = load_word(data, 1)
        version_id = load_word(data, 2)
        operator = load_address(data, 3)
        tee_wallet = load_address(data, 6)
        zk_verified = load_word(data, 7) != 0
        status = load_word(data, 8)
        registered_at = load_word(data, 9)

        # Decode instanceUrl (dynamic string)
        url_offset = load_word(data, 4)
        url_len = load_word(data, url_offset // 32)
        url_start = url_offset + 32
        instance_url = data[url_start:url_start+url_len].decode("utf-8", errors="replace")

        print(f"  instanceId:         {inst_id}  {'✅' if inst_id > 0 else '❌ ZERO — wallet not registered!'}")
        print(f"  appId:              {app_id}  {'✅ matches kmsAppId' if app_id == kms_app_id else f'❌ MISMATCH! kmsAppId={kms_app_id}'}")
        print(f"  versionId:          {version_id}")
        print(f"  operator:           {operator}")
        print(f"  instanceUrl:        {instance_url}")
        print(f"  teeWalletAddress:   {tee_wallet}  {'✅ matches' if tee_wallet.lower() == TEE_WALLET.lower() else '❌ MISMATCH!'}")
        print(f"  zkVerified:         {zk_verified}")
        print(f"  status:             {status} ({STATUS_NAMES.get(status, 'UNKNOWN')})  {'✅ ACTIVE' if status == 0 else '❌ NOT ACTIVE!'}")
        print(f"  registeredAt:       {registered_at}")

        # ── Check 3: Version status ────────────────────────────────────────
        print()
        print("=" * 70)
        print(f"CHECK 3: NovaAppRegistry.getVersion(appId={app_id}, versionId={version_id})")
        print("=" * 70)

        # Encode: getVersion(uint256,uint256)
        ver_selector = function_selector("getVersion(uint256,uint256)")
        ver_calldata = ver_selector + app_id.to_bytes(32, "big") + version_id.to_bytes(32, "big")
        
        try:
            ver_raw = eth_call_raw(NOVA_APP_REGISTRY, ver_calldata)
            
            ver_word0 = load_word(ver_raw, 0)
            ver_data = ver_raw[32:] if ver_word0 == 32 else ver_raw
            
            ver_id = load_word(ver_data, 0)
            # word[1] = offset to versionName
            # word[2] = codeMeasurement (bytes32)
            # word[3] = offset to imageUri
            # word[4] = offset to auditUrl
            # word[5] = offset to auditHash
            # word[6] = offset to githubRunId
            # word[7] = status
            # word[8] = enrolledAt
            # word[9] = enrolledBy
            
            ver_status = load_word(ver_data, 7)
            enrolled_at = load_word(ver_data, 8)
            enrolled_by = load_address(ver_data, 9)

            # Decode versionName
            name_offset = load_word(ver_data, 1)
            name_len = load_word(ver_data, name_offset // 32)
            name_start = name_offset + 32
            ver_name = ver_data[name_start:name_start+name_len].decode("utf-8", errors="replace")

            print(f"  versionId:          {ver_id}")
            print(f"  versionName:        {ver_name}")
            print(f"  status:             {ver_status} ({VERSION_STATUS_NAMES.get(ver_status, 'UNKNOWN')})  {'✅ ENROLLED' if ver_status == 0 else '❌ NOT ENROLLED!'}")
            print(f"  enrolledAt:         {enrolled_at}")
            print(f"  enrolledBy:         {enrolled_by}")
        except Exception as e:
            print(f"  ❌ getVersion call FAILED: {e}")

except Exception as e:
    print(f"  ❌ getInstanceByWallet call FAILED: {e}")
    import traceback; traceback.print_exc()

# ── Check 4: Simulate _isEligibleHashSetter ────────────────────────────────
print()
print("=" * 70)
print("CHECK 4: Simulating _isEligibleHashSetter (exact Solidity logic)")
print("=" * 70)

# The contract does:
#  1. staticcall getInstanceByWallet(sender) → check appId, teeWallet, status
#  2. staticcall getVersion(appId, versionId) → check version status == ENROLLED
# But the key question: in the actual on-chain call, msg.sender is the TEE wallet.
# The TEE wallet signs via Odyn, so msg.sender = TEE wallet address.

print(f"\n  When setMasterSecretHash is called, msg.sender = {TEE_WALLET}")
print(f"  The contract calls getInstanceByWallet({TEE_WALLET}) on NovaAppRegistry")
print()

try:
    # reuse the already decoded values
    checks = []
    checks.append(("novaAppRegistry != address(0)", on_chain_registry != "0x" + "0" * 40))
    checks.append(("kmsAppId != 0", kms_app_id > 0))
    checks.append(("masterSecretHash == 0 (can still set)", hash_is_zero))
    checks.append((f"getInstanceByWallet returns data (instLen >= 320 bytes)", len(raw) >= 320))
    checks.append((f"appId({app_id}) == kmsAppId({kms_app_id})", app_id == kms_app_id))
    checks.append((f"teeWalletAddress({tee_wallet}) == sender({TEE_WALLET})", tee_wallet.lower() == TEE_WALLET.lower()))
    checks.append((f"instanceStatus == ACTIVE (0), got {status}", status == 0))
    
    try:
        checks.append((f"versionStatus == ENROLLED (0), got {ver_status}", ver_status == 0))
    except NameError:
        checks.append(("getVersion succeeds", False))

    all_pass = True
    for desc, ok in checks:
        mark = "✅" if ok else "❌"
        if not ok:
            all_pass = False
        print(f"  {mark} {desc}")

    print()
    if all_pass:
        print("  ✅ All checks PASS — setMasterSecretHash should succeed.")
    else:
        print("  ❌ One or more checks FAILED — this is why NotAuthorizedToSetHash reverted.")
except Exception as e:
    print(f"  Error during summary: {e}")
