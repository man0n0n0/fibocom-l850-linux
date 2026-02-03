#!/usr/bin/env python3
"""
XMM7360 Connection Daemon
Production-ready daemon for Intel XMM7360 LTE modems
Based on xmm7360-pci RPC implementation
"""

import sys
import os
import struct
import time
import signal
import logging
import argparse
import binascii
import itertools
import ipaddress
import hashlib
from pathlib import Path

# Configuration
RPC_DEVICES = ['/dev/xmm0/rpc', '/dev/wwan0xmmrpc0']
NETWORK_INTERFACE = 'wwan0'
DEFAULT_APN = 'web.vodafone.de'
MAX_RETRIES = 5
RETRY_DELAY = 10
IP_FETCH_TIMEOUT = 2
IP_FETCH_MAX_ATTEMPTS = 30

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/xmm7360-daemon.log')
    ]
)
logger = logging.getLogger('xmm7360-daemon')

# RPC Call IDs
RPC_CALL_IDS = {
    'UtaMsSimOpenReq': 0x01,
    'UtaMsCallCsInit': 0x24,
    'UtaMsCbsInit': 0x25,
    'UtaMsSsInit': 0x26,
    'UtaMsSmsInit': 0x30,
    'UtaMsCallPsInitialize': 0x3A,
    'UtaMsCallPsGetNegotiatedDnsReq': 0x47,
    'UtaMsCallPsGetNegIpAddrReq': 0x49,
    'UtaMsCallPsConnectReq': 0x51,
    'UtaMsNetOpen': 0x53,
    'UtaMsNetAttachReq': 0x5C,
    'UtaSysGetInfo': 0x7C,
    'UtaRPCPSConnectSetupReq': 0x7D,
    'UtaRPCPsConnectToDatachannelReq': 0x7E,
    'UtaModeSetReq': 0x12F,
    'CsiFccLockQueryReq': 0x18E,
    'CsiFccLockGenChallengeReq': 0x190,
    'CsiFccLockVerChallengeReq': 0x192,
    'UtaMsCallPsAttachApnConfigReq': 0x1AF,
}

# Unsolicited message IDs
UNSOL_UtaMsNetIsAttachAllowedIndCb = 0x06C


class RPC:
    """XMM7360 RPC Communication Handler - Full Implementation"""
    
    def __init__(self, device_path=None):
        # Find device
        if device_path:
            self.device_path = device_path
        else:
            self.device_path = None
            for dev in RPC_DEVICES:
                if os.path.exists(dev):
                    self.device_path = dev
                    break
        
        if not self.device_path:
            raise IOError('XMM RPC interface does not exist')
        
        self.fd = None
        self.tid_gen = itertools.cycle(range(1, 256))
        self.attach_allowed = False
    
    def open(self):
        """Open RPC device"""
        try:
            self.fd = os.open(self.device_path, os.O_RDWR | os.O_SYNC)
            logger.info(f"Opened RPC device: {self.device_path}")
            return True
        except OSError as e:
            logger.error(f"Failed to open {self.device_path}: {e}")
            return False
    
    def close(self):
        """Close RPC device"""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
            logger.info("Closed RPC device")
    
    # ASN.1 Encoding Functions
    @staticmethod
    def asn_int4(val):
        """Pack 4-byte integer in ASN.1 format"""
        return b'\x02\x04' + struct.pack('>L', val)
    
    @staticmethod
    def take_asn_int(data):
        """Extract ASN.1 integer from bytearray"""
        assert data.pop(0) == 0x02
        l_data = data.pop(0)
        val = 0
        for i in range(l_data):
            val <<= 8
            val |= data.pop(0)
        return val
    
    @staticmethod
    def take_string(data):
        """Extract ASN.1 string from bytearray"""
        t = data.pop(0)
        assert t in [0x55, 0x56, 0x57]
        valid = data.pop(0)
        
        if valid & 0x80:
            value = 0
            for byte in range(valid & 0xf):
                value |= data.pop(0) << (byte * 8)
            valid = value
        
        if t == 0x56:
            valid <<= 1
        elif t == 0x57:
            valid <<= 2
        
        count = RPC.take_asn_int(data)
        padding = RPC.take_asn_int(data)
        
        if count:
            assert count == (valid + padding)
        
        payload = data[:valid]
        for i in range(valid + padding):
            data.pop(0)
        
        return payload
    
    @staticmethod
    def unpack_unknown(data):
        """Unpack ASN.1 data structure"""
        out = []
        data = bytearray(data)
        
        while len(data):
            t = data[0]
            if t == 0x02:
                out.append(RPC.take_asn_int(data))
            elif t in [0x55, 0x56, 0x57]:
                out.append(RPC.take_string(data))
            else:
                raise ValueError(f"unknown type 0x{t:x}")
        
        return out
    
    @staticmethod
    def unpack(fmt, data):
        """Unpack with format string"""
        data = bytearray(data)
        out = []
        for ch in fmt:
            if ch == 'n':
                out.append(RPC.take_asn_int(data))
            elif ch == 's':
                out.append(RPC.take_string(data))
            else:
                raise ValueError(f"unknown format char {ch}")
        return out
    
    @staticmethod
    def pack_string(val, fmt, elem_type):
        """Pack string in ASN.1 format"""
        length_str = ''
        while len(fmt) and fmt[0].isdigit():
            length_str += fmt.pop(0)
        
        length = int(length_str)
        assert len(val) <= length
        valid = len(val)
        
        elem_size = len(struct.pack(elem_type, 0))
        field_type = {1: 0x55, 2: 0x56, 4: 0x57}[elem_size]
        payload = struct.pack(f'{valid}{elem_type}', *val)
        
        count = length * elem_size
        padding = (length - valid) * elem_size
        
        if valid < 128:
            valid_field = struct.pack('B', valid)
        else:
            remain = valid
            valid_field = [0x80]
            while remain > 0:
                valid_field[0] += 1
                valid_field.insert(1, remain & 0xff)
                remain >>= 8
        
        field = struct.pack('B', field_type)
        field += bytes(valid_field)
        field += RPC.pack('LL', count, padding)
        field += payload
        field += b'\0' * padding
        
        return field
    
    @staticmethod
    def pack(fmt, *args):
        """Pack with format string"""
        out = b''
        fmt = list(fmt)
        args = list(args)
        
        while len(fmt):
            arg = args.pop(0)
            ch = fmt.pop(0)
            
            if ch == 'B':
                out += b'\x02\x01' + struct.pack('B', arg)
            elif ch == 'H':
                out += b'\x02\x02' + struct.pack('>H', arg)
            elif ch == 'L':
                out += b'\x02\x04' + struct.pack('>L', arg)
            elif ch == 's':
                out += RPC.pack_string(arg, fmt, 'B')
            elif ch == 'S':
                elem_type = fmt.pop(0)
                out += RPC.pack_string(arg, fmt, elem_type)
            else:
                raise ValueError(f"Unknown format char '{ch}'")
        
        if len(args):
            raise ValueError("Too many args supplied")
        
        return out
    
    def execute(self, cmd, body=None, is_async=False):
        """Execute RPC command"""
        if self.fd is None:
            raise RuntimeError("RPC device not open")
        
        if isinstance(cmd, str):
            cmd = RPC_CALL_IDS[cmd]
        
        if body is None:
            body = self.asn_int4(0)
        
        if is_async:
            tid = 0x11000101
        else:
            tid = 0
        
        tid_word = 0x11000100 | tid
        
        total_length = len(body) + 16
        if tid:
            total_length += 6
        
        header = struct.pack('<L', total_length) + self.asn_int4(total_length) + \
                 self.asn_int4(cmd) + struct.pack('>L', tid_word)
        
        if tid:
            header += self.asn_int4(tid)
        
        packet = header + body
        logger.debug(f"RPC execute 0x{cmd:04x}, {len(packet)} bytes")
        
        # Write
        ret = os.write(self.fd, packet)
        if ret < len(packet):
            raise IOError(f"Write error: {ret}")
        
        # Read responses
        while True:
            resp = self.pump()
            if resp['type'] == 'response':
                return resp
    
    def pump(self):
        """Read and handle RPC message"""
        message = os.read(self.fd, 131072)
        resp = self.handle_message(message)
        
        if resp['type'] == 'unsolicited':
            logger.debug(f"Unsolicited message: 0x{resp['code']:04x}")
            self.handle_unsolicited(resp)
        
        return resp
    
    def handle_message(self, message):
        """Parse RPC message"""
        length = message[:4]
        len1_p = message[4:10]
        code_p = message[10:16]
        txid = message[16:20]
        body = message[20:]
        
        assert len1_p.startswith(b'\x02\x04')
        assert code_p.startswith(b'\x02\x04')
        
        l0 = struct.unpack('<L', length)[0]
        l1 = struct.unpack('>L', len1_p[2:])[0]
        code = struct.unpack('>L', code_p[2:])[0]
        txid = struct.unpack('>L', txid)[0]
        
        if l0 != l1:
            logger.warning("Length mismatch, framing error?")
        
        content = self.unpack_unknown(body)
        
        if txid == 0x11000100:
            t = 'response'
        elif (txid & 0xffffff00) == 0x11000100:
            if code >= 2000:
                t = 'async_ack'
            else:
                t = 'response'
                if content and content[0] == txid:
                    content = content[1:]
                    body = body[6:]
        else:
            t = 'unsolicited'
        
        return {'tid': txid, 'type': t, 'code': code, 'body': body, 'content': content}
    
    def handle_unsolicited(self, message):
        """Handle unsolicited messages"""
        if message['code'] == UNSOL_UtaMsNetIsAttachAllowedIndCb:
            if len(message['content']) > 2:
                self.attach_allowed = message['content'][2]
                logger.info(f"Attach allowed: {self.attach_allowed}")


class XMM7360Modem:
    """XMM7360 Modem Controller"""
    
    def __init__(self, apn=DEFAULT_APN):
        self.apn = apn
        self.rpc = RPC()
        self.connected = False
        self.ip_address = None
        self.dns_servers = {'v4': [], 'v6': []}
    
    def initialize(self):
        """Initialize modem"""
        logger.info("Initializing modem...")
        
        if not self.rpc.open():
            return False
        
        try:
            # Modem initialization sequence (from open_xdatachannel.py)
            logger.info("-> UtaMsSmsInit")
            self.rpc.execute('UtaMsSmsInit')
            
            logger.info("-> UtaMsCbsInit")
            self.rpc.execute('UtaMsCbsInit')
            
            logger.info("-> UtaMsNetOpen")
            self.rpc.execute('UtaMsNetOpen')
            
            logger.info("-> UtaMsCallCsInit")
            self.rpc.execute('UtaMsCallCsInit')
            
            logger.info("-> UtaMsCallPsInitialize")
            self.rpc.execute('UtaMsCallPsInitialize')
            
            logger.info("-> UtaMsSsInit")
            self.rpc.execute('UtaMsSsInit')
            
            logger.info("-> UtaMsSimOpenReq")
            self.rpc.execute('UtaMsSimOpenReq')
            
            # FCC Unlock
            self.do_fcc_unlock()
            
            # Disable airplane mode
            logger.info("-> UtaModeSet (disable airplane mode)")
            self.uta_mode_set(1)
            
            logger.info("Modem initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Modem initialization failed: {e}", exc_info=True)
            self.rpc.close()
            return False
    
    def do_fcc_unlock(self):
        """FCC unlock procedure"""
        try:
            logger.info("Checking FCC lock status...")
            fcc_status = self.rpc.execute('CsiFccLockQueryReq', is_async=True)
            _, fcc_state, fcc_mode = RPC.unpack('nnn', fcc_status['body'])
            
            logger.info(f"FCC lock: state={fcc_state}, mode={fcc_mode}")
            
            if not fcc_mode or fcc_state:
                return
            
            logger.info("Performing FCC unlock...")
            fcc_chal_resp = self.rpc.execute('CsiFccLockGenChallengeReq', is_async=True)
            _, fcc_chal = RPC.unpack('nn', fcc_chal_resp['body'])
            
            chal_bytes = struct.pack('<L', fcc_chal)
            key = bytearray([0x3d, 0xf8, 0xc7, 0x19])
            resp_bytes = hashlib.sha256(chal_bytes + key).digest()
            resp = struct.unpack('<L', resp_bytes[:4])[0]
            
            unlock_resp = self.rpc.execute('CsiFccLockVerChallengeReq',
                                          RPC.pack('L', resp), is_async=True)
            result = RPC.unpack('n', unlock_resp['body'])[0]
            
            if result != 1:
                raise IOError("FCC unlock failed")
            
            logger.info("FCC unlock successful")
            
        except Exception as e:
            logger.warning(f"FCC unlock procedure failed: {e}")
    
    def uta_mode_set(self, mode):
        """Set modem mode"""
        mode_tid = 15
        resp = self.rpc.execute('UtaModeSetReq', RPC.pack('LLL', 0, mode_tid, mode))
        
        if resp['content'][0] != 0:
            raise IOError("UtaModeSet failed")
        
        # Wait for mode set confirmation
        for _ in range(10):
            msg = self.rpc.pump()
            if msg['code'] == 0x130:  # UtaModeSetRspCb
                if msg['content'][0] != mode:
                    raise IOError("UtaModeSet could not set mode - FCC lock enabled?")
                return
        
        logger.warning("UtaModeSet confirmation not received")
    
    def configure_apn(self):
        """Configure APN"""
        logger.info(f"Configuring APN: {self.apn}")
        
        try:
            # Pack APN configuration (from rpc.py: pack_UtaMsCallPsAttachApnConfigReq)
            apn_string = bytearray(101)
            apn_bytes = self.apn.encode('ascii')
            apn_string[:len(apn_bytes)] = apn_bytes
            
            # Simplified APN config - full version has many more fields
            args = [0, b'\0' * 257, 0, b'\0' * 65, b'\0' * 65, b'\0' * 250, 0, b'\0' * 250, 
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                    b'\0' * 20, 0, b'\0' * 101, b'\0' * 257, 0, b'\0' * 65, b'\0' * 65, 
                    b'\0' * 250, 0, b'\0' * 250, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                    0, 0, 0, 0, 0, 0, 0, 0, 0, b'\0' * 20, 0, b'\0' * 101, b'\0' * 257, 
                    0, b'\0' * 65, b'\0' * 65, b'\0' * 250, 0, b'\0' * 250, 0, 0, 0, 0, 
                    0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0x404, 1, 0, 1, 0, 0, b'\0' * 20, 
                    3, apn_string, b'\0' * 257, 0, b'\0' * 65, b'\0' * 65, b'\0' * 250, 0, 
                    b'\0' * 250, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0x404, 
                    1, 0, 1, 0, 0, b'\0' * 20, 3, apn_string, 3, 0]
            
            types = 'Bs260Ls66s65s250Bs252HLLLLLLLLLLLLLLLLLLLLLs20Ls104s260Ls66s65s250Bs252HLLLLLLLLLLLLLLLLLLLLLs20Ls104s260Ls66s65s250Bs252HLLLLLLLLLLLLLLLLLLLLLs20Ls104s260Ls66s65s250Bs252HLLLLLLLLLLLLLLLLLLLLLs20Ls103BL'
            
            apn_body = RPC.pack(types, *args)
            
            self.rpc.execute('UtaMsCallPsAttachApnConfigReq', apn_body, is_async=True)
            logger.info("APN configured")
            return True
            
        except Exception as e:
            logger.error(f"APN configuration failed: {e}", exc_info=True)
            return False
    
    def attach_network(self):
        """Attach to network"""
        logger.info("Attaching to network...")
        
        try:
            attach_body = RPC.pack('BLLLLHHLL', 0, 0, 0, 0, 0, 0xffff, 0xffff, 0, 0)
            attach = self.rpc.execute('UtaMsNetAttachReq', attach_body, is_async=True)
            _, status = RPC.unpack('nn', attach['body'])
            
            if status == 0xffffffff:
                logger.info("Attach failed - waiting for attach_allowed signal")
                
                # Wait for attach_allowed
                max_wait = 30
                for _ in range(max_wait):
                    if self.rpc.attach_allowed:
                        break
                    self.rpc.pump()
                    time.sleep(1)
                
                if not self.rpc.attach_allowed:
                    raise IOError("Timeout waiting for attach_allowed")
                
                # Retry attach
                attach = self.rpc.execute('UtaMsNetAttachReq', attach_body, is_async=True)
                _, status = RPC.unpack('nn', attach['body'])
                
                if status == 0xffffffff:
                    raise IOError("Network attach failed again")
            
            logger.info("Network attach successful")
            return True
            
        except Exception as e:
            logger.error(f"Network attach failed: {e}")
            return False
    
    def get_ip(self):
        """Get IP address and DNS servers"""
        try:
            # Get IP address
            ip_body = RPC.pack('BLL', 0, 0, 0)
            ip_resp = self.rpc.execute('UtaMsCallPsGetNegIpAddrReq', ip_body, is_async=True)
            _, addresses, _, _, _, _ = RPC.unpack('nsnnnn', ip_resp['body'])
            
            # Parse IP addresses
            a1 = ipaddress.IPv4Address(int(binascii.hexlify(addresses[:4]), 16))
            a2 = ipaddress.IPv4Address(int(binascii.hexlify(addresses[4:8]), 16))
            a3 = ipaddress.IPv4Address(int(binascii.hexlify(addresses[8:12]), 16))
            
            # Find valid IP (last non-zero)
            for addr in [a3, a2, a1]:
                if str(addr) != '0.0.0.0':
                    self.ip_address = str(addr)
                    break
            
            # Get DNS servers
            dns_body = RPC.pack('BLL', 0, 0, 0)
            dns_resp = self.rpc.execute('UtaMsCallPsGetNegotiatedDnsReq', dns_body, is_async=True)
            vals = RPC.unpack('n' + 'sn' * 16 + 'nsnnnn', dns_resp['body'])
            
            self.dns_servers = {'v4': [], 'v6': []}
            for i in range(16):
                address, typ = vals[2 * i + 1:2 * i + 3]
                if typ == 1:
                    ip = ipaddress.IPv4Address(int(binascii.hexlify(address[:4]), 16))
                    self.dns_servers['v4'].append(str(ip))
                elif typ == 2:
                    ip = ipaddress.IPv6Address(int(binascii.hexlify(address[:16]), 16))
                    self.dns_servers['v6'].append(str(ip))
            
            return self.ip_address is not None
            
        except Exception as e:
            logger.debug(f"Failed to get IP: {e}")
            return False
    
    def wait_for_ip(self):
        """Wait for IP address assignment"""
        logger.info("Waiting for IP address...")
        
        for attempt in range(IP_FETCH_MAX_ATTEMPTS):
            if self.get_ip():
                logger.info(f"IP address: {self.ip_address}")
                logger.info(f"DNS servers: {', '.join(self.dns_servers['v4'] + self.dns_servers['v6'])}")
                return True
            
            logger.debug(f"IP not ready, attempt {attempt + 1}/{IP_FETCH_MAX_ATTEMPTS}")
            time.sleep(IP_FETCH_TIMEOUT)
        
        logger.error("Timeout waiting for IP address")
        return False
    
    def setup_data_channel(self):
        """Setup data channel"""
        logger.info("Setting up data channel...")
        
        try:
            # UtaMsCallPsConnectReq
            pscr_body = RPC.pack('BLLL', 0, 6, 0, 0)
            pscr = self.rpc.execute('UtaMsCallPsConnectReq', pscr_body, is_async=True)
            
            # UtaRPCPsConnectToDatachannelReq
            path = '/sioscc/PCIE/IOSM/IPS/0'
            bpath = path.encode('ascii') + b'\0'
            dcr_body = RPC.pack('s24', bpath)
            dcr = self.rpc.execute('UtaRPCPsConnectToDatachannelReq', dcr_body)
            
            # UtaRPCPSConnectSetupReq
            csr_req = pscr['body'][:-6] + dcr['body'] + b'\x02\x04\0\0\0\0'
            self.rpc.execute('UtaRPCPSConnectSetupReq', csr_req)
            
            self.connected = True
            logger.info("Data channel established")
            return True
            
        except Exception as e:
            logger.error(f"Data channel setup failed: {e}", exc_info=True)
            return False
    
    def disconnect(self):
        """Disconnect"""
        logger.info("Disconnecting...")
        self.connected = False
        self.rpc.close()
    
    def full_connect(self):
        """Complete connection sequence"""
        if not self.initialize():
            return False
        
        if not self.configure_apn():
            return False
        
        if not self.attach_network():
            return False
        
        if not self.wait_for_ip():
            return False
        
        if not self.setup_data_channel():
            return False
        
        return True


class Daemon:
    """Systemd-compatible daemon"""
    
    def __init__(self, apn=DEFAULT_APN, auto_reconnect=True):
        self.modem = XMM7360Modem(apn)
        self.auto_reconnect = auto_reconnect
        self.running = True
        self.retry_count = 0
        
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def run(self):
        """Main daemon loop"""
        logger.info("XMM7360 Daemon starting...")
        logger.info(f"APN: {self.modem.apn}")
        logger.info(f"Auto-reconnect: {self.auto_reconnect}")
        
        while self.running:
            try:
                logger.info(f"Connection attempt {self.retry_count + 1}/{MAX_RETRIES if not self.auto_reconnect else '∞'}")
                
                if self.modem.full_connect():
                    logger.info("✓ Modem connected successfully")
                    logger.info(f"  IP: {self.modem.ip_address}")
                    logger.info(f"  DNS: {', '.join(self.modem.dns_servers['v4'])}")
                    self.retry_count = 0
                    
                    # Keep alive - monitor connection
                    while self.running and self.modem.connected:
                        time.sleep(30)
                        # TODO: Add connection health checks
                    
                else:
                    self.retry_count += 1
                    if not self.auto_reconnect and self.retry_count >= MAX_RETRIES:
                        logger.error("Max retries reached, exiting")
                        break
                    
                    if self.auto_reconnect:
                        logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                        time.sleep(RETRY_DELAY)
                    else:
                        break
                        
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                if self.auto_reconnect:
                    time.sleep(RETRY_DELAY)
                else:
                    break
        
        self.modem.disconnect()
        logger.info("XMM7360 Daemon stopped")


def main():
    parser = argparse.ArgumentParser(description='XMM7360 Connection Daemon')
    parser.add_argument('--apn', default=DEFAULT_APN, help='APN to use')
    parser.add_argument('--no-reconnect', action='store_true', help='Disable auto-reconnect')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    daemon = Daemon(apn=args.apn, auto_reconnect=not args.no_reconnect)
    daemon.run()


if __name__ == '__main__':
    main()
