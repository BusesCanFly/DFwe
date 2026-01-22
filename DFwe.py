#!/usr/bin/env python3

import os
import time
import sys
import platform
import argparse
from datetime import datetime
from pathlib import Path
import serial
import serial.tools.list_ports
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import hashlib

TARGET_LABELS = ["RP2350", "RPI-RP2"]  # Support both RP2350 and RP2040
SERIAL_POLL_INTERVAL = 0.2           # seconds - how often to check for serial ports
DRIVE_POLL_INTERVAL = 0.3            # seconds - how often to check for drives
DFU_WAIT_TIME = 1.5                  # seconds - to wait for DFU mode to activate
SERIAL_PORT_RESET_TIME = 2.0         # seconds - before allowing same serial port to be retriggered
FLASH_COOLDOWN_TIME = 5.0            # seconds -  ignore serial ports after a flash completes
MAX_PARALLEL_DFU = 10                # Maximum parallel DFU triggers
FILE_COPY_BUFFER_SIZE = 1024 * 1024  # 1MB buffer for faster copying

IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'

def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

def get_file_hash(filepath, buffer_size=FILE_COPY_BUFFER_SIZE):
    """Calculate MD5 hash of a file for verification"""
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        while chunk := f.read(buffer_size):
            md5.update(chunk)
    return md5.hexdigest()

def find_rp2350_serial_ports():
    """Find all serial ports that might be RP2350/RP2040 devices"""
    ports = []
    for port in serial.tools.list_ports.comports():
        # RP2350/RP2040 typically shows up with VID 2E8A (Raspberry Pi)
        if port.vid == 0x2E8A:
            ports.append({
                'device': port.device,
                'serial_number': port.serial_number or port.device,
                'description': port.description
            })
    return ports

def trigger_dfu_mode_single(port_info):
    """Trigger DFU mode for a single port (thread-safe)"""
    port_device = port_info['device']
    serial_num = port_info['serial_number']
    try:
        # Open at 1200 baud to trigger the bootloader
        ser = serial.Serial(port_device, 1200, timeout=1)
        ser.close()
        return (serial_num, port_device, True, None)
    except Exception as e:
        return (serial_num, port_device, False, str(e))

def trigger_dfu_mode_parallel(ports_to_trigger):
    """Trigger DFU mode on multiple ports in parallel"""
    if not ports_to_trigger:
        return []
    
    results = []
    print(f"[{get_timestamp()}] Triggering DFU on {len(ports_to_trigger)} device(s)...", flush=True)
    
    with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_DFU, len(ports_to_trigger))) as executor:
        future_to_port = {executor.submit(trigger_dfu_mode_single, port): port for port in ports_to_trigger}
        
        for future in as_completed(future_to_port):
            serial_num, port_device, success, error = future.result()
            if success:
                print(f"[{get_timestamp()}] ✓ DFU triggered on {port_device}")
            else:
                print(f"[{get_timestamp()}] ✗ DFU failed on {port_device}: {error}")
            results.append((serial_num, success))
    
    return results

def is_uf2_bootloader_drive(mountpoint):
    """Check if a mountpoint is a UF2 bootloader drive - returns (is_valid, info_content)"""
    try:
        mount_path = Path(mountpoint)
        info_file = mount_path / "INFO_UF2.TXT"
        
        if not info_file.exists():
            return False, None
        
        # Try multiple encodings for cross-platform compatibility
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                content = info_file.read_text(encoding=encoding)
                # Check if it mentions RP2350, RP2040, or RPI-RP2
                if any(label in content for label in ['RP2350', 'RP2040', 'RPI-RP2']):
                    return True, content
                break  # Successfully read, don't try other encodings
            except UnicodeDecodeError:
                continue
        
        return False, None
    except Exception:
        return False, None

def get_drive_label(partition):
    """Get the volume label for a partition (cross-platform)"""
    try:
        if IS_WINDOWS:
            # On Windows, try to get the volume label
            import ctypes
            kernel32 = ctypes.windll.kernel32
            volumeNameBuffer = ctypes.create_unicode_buffer(1024)
            fileSystemNameBuffer = ctypes.create_unicode_buffer(1024)
            
            # Extract drive letter (e.g., "C:\" from "C:\")
            drive_letter = str(Path(partition.mountpoint))
            if not drive_letter.endswith('\\'):
                drive_letter += '\\'
            
            result = kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive_letter),
                volumeNameBuffer,
                ctypes.sizeof(volumeNameBuffer),
                None, None, None,
                fileSystemNameBuffer,
                ctypes.sizeof(fileSystemNameBuffer)
            )
            
            if result:
                return volumeNameBuffer.value
        else:
            # On Unix-like systems, the label is typically in the mountpoint path
            return Path(partition.mountpoint).name
    except Exception:
        pass
    
    return None

def normalize_drive_path(path):
    """Normalize drive path for consistent comparison across platforms"""
    try:
        # Convert to absolute path and resolve any symlinks
        normalized = Path(path).resolve()
        return str(normalized)
    except Exception:
        return str(path)

def fast_file_copy(src, dst, buffer_size=FILE_COPY_BUFFER_SIZE, force_sync=False):
    """Optimized file copy without metadata preservation
    
    Args:
        src: Source file path
        dst: Destination file path
        buffer_size: Read/write buffer size (default 1MB)
        force_sync: If True, force filesystem sync (very slow, default False)
    """
    src_path = Path(src)
    dst_path = Path(dst)
    
    with open(src_path, 'rb') as fsrc:
        with open(dst_path, 'wb') as fdst:
            while chunk := fsrc.read(buffer_size):
                fdst.write(chunk)
            
            # Only force sync if explicitly requested
            if force_sync and hasattr(fdst, 'fileno'):
                try:
                    os.fsync(fdst.fileno())
                except Exception:
                    pass

class SerialMonitor(threading.Thread):
    """Background thread for monitoring serial ports and triggering DFU"""
    
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.triggered_serial_ports = {}  # serial_number -> timestamp
        self.pending_dfu_triggers = {}  # serial_number -> timestamp
        self.previous_serial_ports = set()
        self.flash_cooldown_until = 0
        self.lock = threading.Lock()
        
    def run(self):
        while self.running:
            try:
                current_time = time.time()
                
                # Check if we're in flash cooldown period
                with self.lock:
                    in_cooldown = current_time < self.flash_cooldown_until
                
                if in_cooldown:
                    time.sleep(SERIAL_POLL_INTERVAL)
                    continue
                
                # Check for serial ports and trigger DFU
                current_serial_ports_data = find_rp2350_serial_ports()
                current_serial_numbers = {p['serial_number'] for p in current_serial_ports_data}
                
                with self.lock:
                    # Detect disconnected serial ports and allow retriggering
                    disconnected_ports = self.previous_serial_ports - current_serial_numbers
                    for serial_num in disconnected_ports:
                        if serial_num in self.triggered_serial_ports:
                            trigger_time = self.triggered_serial_ports[serial_num]
                            if current_time - trigger_time > SERIAL_PORT_RESET_TIME:
                                del self.triggered_serial_ports[serial_num]
                        if serial_num in self.pending_dfu_triggers:
                            del self.pending_dfu_triggers[serial_num]
                    
                    self.previous_serial_ports = current_serial_numbers
                    
                    # Collect ports that need DFU triggering
                    ports_to_trigger = []
                    for port_info in current_serial_ports_data:
                        serial_num = port_info['serial_number']
                        
                        if serial_num in self.triggered_serial_ports or serial_num in self.pending_dfu_triggers:
                            continue
                        
                        ports_to_trigger.append(port_info)
                
                # Trigger DFU on all ports in parallel
                if ports_to_trigger:
                    trigger_results = trigger_dfu_mode_parallel(ports_to_trigger)
                    
                    with self.lock:
                        for serial_num, success in trigger_results:
                            self.triggered_serial_ports[serial_num] = current_time
                            if success:
                                self.pending_dfu_triggers[serial_num] = current_time
                
                # Clean up old pending DFU triggers
                with self.lock:
                    expired_triggers = [
                        serial_num for serial_num, trigger_time in self.pending_dfu_triggers.items()
                        if current_time - trigger_time > DFU_WAIT_TIME
                    ]
                    for serial_num in expired_triggers:
                        del self.pending_dfu_triggers[serial_num]
                
            except Exception as e:
                print(f"[{get_timestamp()}] SerialMonitor error: {e}")
            
            time.sleep(SERIAL_POLL_INTERVAL)
    
    def stop(self):
        self.running = False
    
    def clear_pending_triggers(self):
        """Clear pending DFU triggers (called when drives are detected)"""
        with self.lock:
            self.pending_dfu_triggers.clear()
    
    def start_flash_cooldown(self):
        """Start cooldown period to prevent re-triggering devices that just finished flashing"""
        with self.lock:
            self.flash_cooldown_until = time.time() + FLASH_COOLDOWN_TIME

class DriveMonitor(threading.Thread):
    """Background thread for monitoring bootloader drives with intelligent caching"""
    
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.current_drives = set()
        self.validated_drives = {}  # mountpoint -> (is_valid, timestamp)
        self.lock = threading.Lock()
        
    def run(self):
        while self.running:
            try:
                current_time = time.time()
                found_drives = set()
                
                for partition in psutil.disk_partitions(all=False):
                    if not partition.mountpoint:
                        continue
                    
                    try:
                        mountpoint = normalize_drive_path(partition.mountpoint)
                        
                        # Check cache first
                        if mountpoint in self.validated_drives:
                            is_valid, cache_time = self.validated_drives[mountpoint]
                            # Cache valid for 5 seconds
                            if current_time - cache_time < 5.0 and is_valid:
                                found_drives.add(mountpoint)
                                continue
                        
                        # Get volume label (cross-platform)
                        label = get_drive_label(partition)
                        
                        # Check if this might be our target drive
                        is_candidate = False
                        
                        if label:
                            # Check if label matches any of our target labels
                            if any(label == target or label.startswith(target) for target in TARGET_LABELS):
                                is_candidate = True
                        elif any(target in partition.mountpoint for target in TARGET_LABELS):
                            is_candidate = True
                        elif IS_MACOS and '/Volumes/' in partition.mountpoint:
                            # On macOS, check volume name
                            volume_name = Path(partition.mountpoint).name
                            if any(volume_name == target or volume_name.startswith(target) for target in TARGET_LABELS):
                                is_candidate = True
                        
                        if is_candidate:
                            # Verify with INFO_UF2.TXT
                            is_valid, _ = is_uf2_bootloader_drive(mountpoint)
                            self.validated_drives[mountpoint] = (is_valid, current_time)
                            if is_valid:
                                found_drives.add(mountpoint)
                        
                    except (PermissionError, OSError):
                        continue
                
                with self.lock:
                    self.current_drives = found_drives
                    
                    # Clean up stale cache entries
                    stale_entries = set(self.validated_drives.keys()) - found_drives
                    for stale in stale_entries:
                        if stale in self.validated_drives:
                            _, cache_time = self.validated_drives[stale]
                            if current_time - cache_time > 10.0:
                                del self.validated_drives[stale]
                
            except Exception as e:
                print(f"[{get_timestamp()}] DriveMonitor error: {e}")
            
            time.sleep(DRIVE_POLL_INTERVAL)
    
    def get_drives(self):
        """Get current list of drives (thread-safe)"""
        with self.lock:
            return list(self.current_drives)
    
    def stop(self):
        self.running = False

def flash_drive_worker(drive, firmware_file, source_hash, verify_writes, flashed_drives, flashed_count_lock, results_queue):
    """Worker function to flash a single drive (runs in separate thread)"""
    try:
        drive_path = Path(drive)
        
        # Get a readable drive name
        if IS_WINDOWS:
            drive_name = str(drive_path)  # e.g., "E:\"
        else:
            drive_name = drive_path.name or str(drive_path)
        
        print(f"[{get_timestamp()}] [{drive_name}] Starting flash...")
        
        dest_path = drive_path / firmware_file
        
        # Fast copy without metadata and without fsync
        fast_file_copy(firmware_file, dest_path, force_sync=False)
        
        # Verify write if enabled
        if verify_writes and source_hash:
            try:
                dest_hash = get_file_hash(dest_path)
                if dest_hash != source_hash:
                    raise Exception("Verification failed: hash mismatch")
                print(f"[{get_timestamp()}] [{drive_name}] ✓ Verified")
            except Exception as verify_error:
                print(f"[{get_timestamp()}] [{drive_name}] ✗ Verification failed: {verify_error}")
                results_queue.put(('error', drive))
                return
        
        print(f"[{get_timestamp()}] [{drive_name}] ✓ Flash successful!")
        results_queue.put(('success', drive))
        
    except Exception as e:
        drive_name = Path(drive).name or str(drive)
        print(f"[{get_timestamp()}] [{drive_name}] ✗ Flash failed: {e}")
        results_queue.put(('error', drive))

def main():
    parser = argparse.ArgumentParser(
        description='AutoFlash - Automated RP2040/RP2350 firmware flasher',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('firmware', nargs='?', default='firmware.uf2',
        help='Firmware file to flash (default: firmware.uf2)')
    parser.add_argument('--verify', action='store_true',
        help='Enable write verification (slower)')
    args = parser.parse_args()
    
    firmware_path = Path(args.firmware)
    
    if not firmware_path.exists():
        print(f"Error: Firmware file '{args.firmware}' not found!")
        sys.exit(1)
    
    # Pre-calculate firmware hash for verification
    if args.verify:
        print("Calculating firmware hash for verification...")
        firmware_hash = get_file_hash(firmware_path)
    else:
        firmware_hash = None
    
    print(f"                                                       ")
    print(f"▄████▄ ▄▄ ▄▄ ▄▄▄▄▄▄ ▄▄▄  ██████ ▄▄     ▄▄▄   ▄▄▄▄ ▄▄ ▄▄")
    print(f"██▄▄██ ██ ██   ██  ██▀██ ██▄▄   ██    ██▀██ ███▄▄ ██▄██")
    print(f"██  ██ ▀███▀   ██  ▀███▀ ██     ██▄▄▄ ██▀██ ▄▄██▀ ██ ██")
    print(f"         s/o DisCo                              v2.5   ")
    print(f"                                                       ")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Firmware: {args.firmware}")
    print(f"Verification: {'ENABLED' if args.verify else 'DISABLED (for speed)'}\n")
    print(f"Waiting for RP2040/RP2350 devices...")
    print("Press Ctrl+C to stop.\n")

    flashed_drives = {}  # drive_path -> timestamp
    previous_drives = set()
    flashed_count = 0
    active_threads = {}
    results_queue = Queue()
    flashed_count_lock = threading.Lock()

    serial_monitor = SerialMonitor()
    drive_monitor = DriveMonitor()
    
    serial_monitor.start()
    drive_monitor.start()
    
    print(f"[{get_timestamp()}] Background monitors started (serial: {SERIAL_POLL_INTERVAL}s, drives: {DRIVE_POLL_INTERVAL}s)\n")

    try:
        while True:
            current_time = time.time()
            
            # Process completed flash operations
            while not results_queue.empty():
                result_type, drive = results_queue.get()
                if drive in active_threads:
                    del active_threads[drive]
                
                if result_type == 'success':
                    with flashed_count_lock:
                        flashed_count += 1
                    print(f"Total Flashed: {flashed_count}\n")
                    serial_monitor.start_flash_cooldown()
                
                flashed_drives[drive] = current_time
            
            # Get current drives from monitor
            current_drives = drive_monitor.get_drives()
            
            # Detect drives that have reconnected
            for drive in current_drives:
                if drive in flashed_drives and drive not in previous_drives:
                    flash_age = current_time - flashed_drives[drive]
                    if flash_age > 3.0:
                        del flashed_drives[drive]
            
            # Clear old flash records for disconnected drives
            disconnected_drives = previous_drives - set(current_drives)
            for drive in disconnected_drives:
                if drive in flashed_drives:
                    flash_age = current_time - flashed_drives[drive]
                    if flash_age > 10.0:
                        del flashed_drives[drive]
            
            previous_drives = set(current_drives)
            
            # Flash any unflashed drives
            new_flashes_started = False
            for drive in current_drives:
                if drive in flashed_drives or drive in active_threads:
                    continue
                
                drive_name = Path(drive).name or str(drive)
                print(f"[{get_timestamp()}] Detected RP2040/RP2350 drive at {drive}")
                
                thread = threading.Thread(
                    target=flash_drive_worker,
                    args=(drive, args.firmware, firmware_hash, args.verify, flashed_drives, flashed_count_lock, results_queue),
                    daemon=True
                )
                thread.start()
                active_threads[drive] = thread
                new_flashes_started = True
            
            if new_flashes_started:
                serial_monitor.clear_pending_triggers()
            
            time.sleep(0.05)
            
    except KeyboardInterrupt:
        print(f"\n[{get_timestamp()}] Stopping flasher...")
        
        serial_monitor.stop()
        drive_monitor.stop()
        
        if active_threads:
            print(f"Waiting for {len(active_threads)} active flash operations to complete...")
            for thread in active_threads.values():
                thread.join(timeout=5.0)
        
        print(f"Total devices flashed: {flashed_count}")

if __name__ == "__main__":
    main()