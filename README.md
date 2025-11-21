# CAN-FD-Security-Gateway-Attack-Defense-HW

The code provided simulatesw a CAN-FD security gateway: one thread sends real ECU messages with a valid MAC, another thread spams spoofed messages with a bad MAC, and the gateway thread receives and filters all traffic using rate-limiting and MAC verification. The script shows how the gateway blocks attacker frames while forwarding only authenticated, properly-paced critical messages.
