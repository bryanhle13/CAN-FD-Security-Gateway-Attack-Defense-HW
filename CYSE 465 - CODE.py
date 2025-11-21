import can
import threading
import time
import struct
import sys

CHANNEL = "demo"         
rx_ready = threading.Event()

CRITICAL_ID = 0x200       
SECRET_KEY = 0x5A         
MAX_RATE_PER_SEC = 5      


def make_bus():
    try:
        return can.interface.Bus(interface="virtual", channel=CHANNEL)
    except TypeError:
        return can.interface.Bus(bustype="virtual", channel=CHANNEL)


def compute_mac(payload_without_mac):
    s = SECRET_KEY
    for b in payload_without_mac:
        s ^= b
    return s & 0xFF


def pack_critical_data(rpm, coolant_temp, fuel_level):
    base = struct.pack("<HBB", rpm, coolant_temp, fuel_level)  
    mac = compute_mac(base).to_bytes(1, "little")              
    padded = base + mac + b"\x00\x00\x00"
    return padded  


def sender_legit():
    """Simulate a legitimate ECU sending correctly authenticated critical messages."""
    bus = make_bus()
    rx_ready.wait(timeout=2)

    for i in range(3):
        payload = pack_critical_data(rpm=2500 + i * 100, coolant_temp=90, fuel_level=70)
        msg = can.Message(
            arbitration_id=CRITICAL_ID,
            is_extended_id=False,
            data=payload,
            is_fd=True,      
        )
        bus.send(msg)
        print(f"[LEGIT] sent ID=0x{CRITICAL_ID:X} DATA={payload.hex(' ').upper()}", flush=True)
        time.sleep(0.5)

    bus.shutdown()


def sender_attacker():
    """Simulate an attacker spoofing the same ID with bad MAC and higher rate."""
    bus = make_bus()
    rx_ready.wait(timeout=2)

    fake_base = struct.pack("<HBB", 6000, 40, 5)   

    bad_mac = (compute_mac(fake_base) ^ 0xFF) & 0xFF  
    fake_payload = fake_base + bad_mac.to_bytes(1, "little") + b"\x00\x00\x00"

    start = time.time()
    while time.time() - start < 2.0:  
        msg = can.Message(
            arbitration_id=CRITICAL_ID,
            is_extended_id=False,
            data=fake_payload,
            is_fd=True,
        )
        bus.send(msg)
        print(f"[ATTACK] sent spoofed ID=0x{CRITICAL_ID:X} DATA={fake_payload.hex(' ').upper()}",
              flush=True)
        time.sleep(0.05)

    bus.shutdown()


def gateway_with_defense():
    bus = make_bus()
    print(f"[GW] listening... (python {sys.version.split()[0]}, python-can {can.__version__})",
          flush=True)
    rx_ready.set()

 
    id_timestamps = {}

    t_end = time.time() + 8  
    try:
        while time.time() < t_end:
            msg = bus.recv(timeout=1.0)
            if not msg:
                continue

            now = time.time()
            msg_id = msg.arbitration_id
            data = bytes(msg.data)

            print(f"[GW] RX ID=0x{msg_id:X} DLC={msg.dlc} DATA={data.hex(' ').upper()}",
                  flush=True)

            if msg_id != CRITICAL_ID:
                print("      -> forwarded (non-critical ID)", flush=True)
                continue

            ts_list = id_timestamps.get(msg_id, [])
            ts_list = [ts for ts in ts_list if now - ts < 1.0]
            ts_list.append(now)
            id_timestamps[msg_id] = ts_list

            if len(ts_list) > MAX_RATE_PER_SEC:
                print("      -> BLOCKED (rate limit exceeded)", flush=True)
                continue

            if len(data) < 5:
                print("      -> BLOCKED (payload too short for MAC)", flush=True)
                continue

            base = data[:4]
            recv_mac = data[4]
            expected_mac = compute_mac(base)

            if recv_mac != expected_mac:
                print(f"      -> BLOCKED (bad MAC: got 0x{recv_mac:02X}, expected 0x{expected_mac:02X})",
                      flush=True)
                continue

            rpm, temp, fuel = struct.unpack("<HBB", base)
            print(f"      -> FORWARDED (rpm={rpm}, temp={temp}, fuel={fuel})", flush=True)
    finally:
        bus.shutdown()
        print("[GW] shutdown cleanly", flush=True)


def main():
    gw_thread = threading.Thread(target=gateway_with_defense, daemon=True)
    gw_thread.start()

    legit_thread = threading.Thread(target=sender_legit, daemon=True)
    attacker_thread = threading.Thread(target=sender_attacker, daemon=True)

    legit_thread.start()
    attacker_thread.start()

    legit_thread.join()
    attacker_thread.join()
    gw_thread.join()

    print("[SYS] Demo complete", flush=True)


if __name__ == "__main__":
    main()