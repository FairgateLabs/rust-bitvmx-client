#pip install requests pyyaml
import requests
import yaml 

RPC_URL = "https://distinguished-intensive-frost.btc-testnet.quiknode.pro/38d0f064dc8e72fe44d8a9a762d448bc64c54619/"


SECS_SYNC = 1
SECS_UPDATE = 1

def get_block_height():
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getblockcount",
        "params": []
    }
    response = requests.post(RPC_URL, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()["result"]

def patch_yaml_height(filepath, height):
    with open(filepath, "r") as f:
        data = yaml.safe_load(f)
    data["coordinator_settings"]["monitor_settings"]["indexer_settings"]["checkpoint_height"] = height

    if "coordinator" in data:
        data["coordinator"]["throtthle_bitcoin_updates_until_sync"] = SECS_SYNC
        data["coordinator"]["throtthle_bitcoin_updates"] = SECS_UPDATE
    with open(filepath, "w") as f:
        yaml.dump(data, f, sort_keys=False)

def get_estimate_fee(conf_target=1):
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "estimatesmartfee",
        "params": [conf_target]
    }
    response = requests.post(RPC_URL, headers=headers, json=payload)
    response.raise_for_status()
    print(response.json())
    result = response.json()["result"]
    return result.get("feerate")

if __name__ == "__main__":
    height = get_block_height()
    print(get_estimate_fee())
    for i in range(1, 5):
        patch_yaml_height(f"config/testnet_op_{i}.yaml", height)
    print(f"Updated checkpoint_height to {height} in all files.")