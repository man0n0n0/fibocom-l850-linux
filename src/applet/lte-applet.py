#!/usr/bin/env python3
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('AppIndicator3', '0.1')
from gi.repository import Gtk, AppIndicator3, GLib
import subprocess
import re

class LTEApplet:
    def __init__(self):
        self.indicator = AppIndicator3.Indicator.new(
            "lte-applet",
            "network-cellular-offline",
            AppIndicator3.IndicatorCategory.SYSTEM_SERVICES
        )
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self._last_icon = None  # Track icon changes
        self._last_status = None  # Track status changes
        self.indicator.set_menu(self.create_menu())
        
        # Update status every 5 seconds
        GLib.timeout_add_seconds(3, self.update_status)
        self.update_status()

    def create_menu(self):
        menu = Gtk.Menu()
        
        # Status item (non-clickable)
        self.status_item = Gtk.MenuItem(label="Checking...")
        self.status_item.set_sensitive(False)
        menu.append(self.status_item)
        
        # IP item (non-clickable)
        self.ip_item = Gtk.MenuItem(label="IP: --.--.--.--")
        self.ip_item.set_sensitive(False)
        menu.append(self.ip_item)
        
        # Quality item (non-clickable)
        self.quality_item = Gtk.MenuItem(label="Quality: Unknown")
        self.quality_item.set_sensitive(False)
        menu.append(self.quality_item)
        
        menu.append(Gtk.SeparatorMenuItem())
        
        # Connect/Disconnect toggle
        self.toggle_item = Gtk.MenuItem(label="Connect")
        self.toggle_item.connect("activate", self.toggle_connection)
        menu.append(self.toggle_item)
        
        # Suspend/Resume toggle
        self.suspend_item = Gtk.MenuItem(label="Suspend")
        self.suspend_item.connect("activate", self.toggle_suspend)
        menu.append(self.suspend_item)
        
        menu.append(Gtk.SeparatorMenuItem())
        
        # Restart
        restart_item = Gtk.MenuItem(label="Restart")
        restart_item.connect("activate", self.restart_connection)
        menu.append(restart_item)
        
        # Show logs
        logs_item = Gtk.MenuItem(label="Show Logs")
        logs_item.connect("activate", self.show_logs)
        menu.append(logs_item)
        
        menu.append(Gtk.SeparatorMenuItem())
        
        # Quit
        quit_item = Gtk.MenuItem(label="Quit Applet")
        quit_item.connect("activate", self.quit)
        menu.append(quit_item)
        
        menu.show_all()
        return menu

    def set_icon_and_label(self, icon_name):
        """Set icon without deprecation warning and force refresh"""
        # Force icon change by setting to blank first if changing state
        if hasattr(self, '_last_icon') and self._last_icon != icon_name:
            self.indicator.set_icon_full("", "")
            GLib.idle_add(lambda: self.indicator.set_icon_full(icon_name, "LTE Status"))
        else:
            self.indicator.set_icon_full(icon_name, "LTE Status")
        self._last_icon = icon_name

    def force_ui_refresh(self):
        """Force complete UI refresh"""
        # Recreate the menu to force update
        self.indicator.set_menu(self.create_menu())
        return False

    def manage_wifi(self, enable):
        """Enable or disable WiFi based on LTE status"""
        try:
            if enable:
                # Enable WiFi when LTE disconnects/suspends
                subprocess.run(['nmcli', 'radio', 'wifi', 'on'], check=False)
            else:
                # Disable WiFi when LTE connects/resumes
                subprocess.run(['nmcli', 'radio', 'wifi', 'off'], check=False)
        except:
            pass

    def update_status(self):
        try:
            # Check if service is active
            result = subprocess.run(['systemctl', 'is-active', 'xmm7360'], 
                                    capture_output=True, text=True, timeout=2)
            
            if result.stdout.strip() == 'active':
                # Check interface status
                ip_result = subprocess.run(['ip', 'addr', 'show', 'wwan0'], 
                                          capture_output=True, text=True, timeout=2)
                
                # Extract IP
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ip_result.stdout)
                
                if ip_match:
                    ip = ip_match.group(1)
                    
                    # Check if interface is up - multiple detection methods
                    is_up = False
                    
                    # Method 1: Check 'state UP' or 'UP' flags in output
                    if 'state UP' in ip_result.stdout or 'UP,LOWER_UP' in ip_result.stdout:
                        is_up = True
                    elif '<POINTOPOINT,NOARP,UP,LOWER_UP>' in ip_result.stdout or '<UP,' in ip_result.stdout:
                        is_up = True
                    
                    # Method 2: Check operstate file
                    if not is_up:
                        try:
                            with open('/sys/class/net/wwan0/operstate', 'r') as f:
                                state = f.read().strip()
                                if state in ['up', 'unknown']:  # 'unknown' is common for wwan
                                    is_up = True
                        except:
                            pass
                    
                    # Method 3: If we have IP and can't determine state, assume up
                    if not is_up and ip_match:
                        # Try a quick ping to determine if it's really up
                        quick_ping = subprocess.run(['ping', '-I', 'wwan0', '-c', '1', '-W', '1', '8.8.8.8'],
                                                   capture_output=True, text=True, timeout=3)
                        if quick_ping.returncode == 0:
                            is_up = True
                    
                    print(f"DEBUG: IP={ip}, is_up={is_up}")
                    
                    if is_up:
                        # Interface is UP - test connectivity
                        print(f"DEBUG: Interface detected as UP, testing connectivity...")
                        ping_result = subprocess.run(['ping', '-I', 'wwan0', '-c', '2', '-W', '2', '8.8.8.8'],
                            capture_output=True, text=True, timeout=5)
                        
                        if ping_result.returncode == 0:
                            # Extract latency
                            latency_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', ping_result.stdout)
                            latency = int(float(latency_match.group(1))) if latency_match else None
                            
                            # Extract packet loss
                            loss_match = re.search(r'(\d+)% packet loss', ping_result.stdout)
                            loss = int(loss_match.group(1)) if loss_match else 100
                            
                            # Determine quality and icon
                            if latency and latency < 50 and loss == 0:
                                quality = "Excellent"
                                icon = "network-cellular-signal-excellent"
                            elif latency and latency < 100 and loss < 10:
                                quality = "Good"
                                icon = "network-cellular-signal-good"
                            elif latency and latency < 150 and loss < 20:
                                quality = "Fair"
                                icon = "network-cellular-signal-ok"
                            elif latency and latency < 200 and loss < 30:
                                quality = "Poor"
                                icon = "network-cellular-signal-weak"
                            else:
                                quality = "Very Poor"
                                icon = "network-cellular-signal-none"
                            
                            print(f"DEBUG: Connected - Quality: {quality}, Latency: {latency}ms")

                            # Check if status changed
                            new_status = "Connected"
                            if self._last_status != new_status:
                                print(f"DEBUG: Status changed from {self._last_status} to {new_status}, recreating menu")
                                self._last_status = new_status
                                # Recreate entire menu to force update
                                GLib.idle_add(lambda: (self.indicator.set_menu(self.create_menu()), False)[1])

                            self.status_item.set_label("Status: Connected")
                            self.ip_item.set_label(f"IP: {ip}")
                            if latency:
                                self.quality_item.set_label(f"{quality} | {latency}ms | Loss: {loss}%")
                            else:
                                self.quality_item.set_label(f"Quality: {quality}")
                            
                            self.set_icon_and_label(icon)
                            self.toggle_item.set_label("Disconnect")
                            self.suspend_item.set_label("Suspend")
                            self.suspend_item.set_sensitive(True)
                            
                            # Force menu items to update visually
                            self.status_item.show()
                            self.ip_item.show()
                            self.quality_item.show()
                        else:
                            # Ping failed but interface is up
                            print(f"DEBUG: Ping failed, checking route...")
                            # Check if route exists
                            route_check = subprocess.run(['ip', 'route', 'show', 'dev', 'wwan0'],
                                                        capture_output=True, text=True, timeout=2)
                            if route_check.stdout.strip():
                                # Route exists but no connectivity
                                print(f"DEBUG: Route exists but no ping response")
                                self.status_item.set_label("Status: No Internet")
                                self.ip_item.set_label(f"IP: {ip}")
                                self.quality_item.set_label("Quality: No connectivity")
                                self.set_icon_and_label("network-cellular-signal-none")
                            else:
                                # No route yet - resuming
                                print(f"DEBUG: No route, still resuming")
                                self.status_item.set_label("Status: Resuming...")
                                self.ip_item.set_label(f"IP: {ip}")
                                self.quality_item.set_label("Quality: Configuring...")
                                self.set_icon_and_label("network-cellular-acquiring")
                            
                            self.toggle_item.set_label("Disconnect")
                            self.suspend_item.set_label("Suspend")
                            self.suspend_item.set_sensitive(True)
                    else:
                        # Interface down (suspended)
                        print(f"DEBUG: Interface detected as DOWN/suspended")

                        # Check if status changed
                        new_status = "Suspended"
                        if self._last_status != new_status:
                            print(f"DEBUG: Status changed from {self._last_status} to {new_status}, recreating menu")
                            self._last_status = new_status
                            # Recreate entire menu to force update
                            GLib.idle_add(lambda: (self.indicator.set_menu(self.create_menu()), False)[1])

                        self.status_item.set_label("Status: Suspended")
                        self.ip_item.set_label(f"IP: {ip} (inactive)")
                        self.quality_item.set_label("Quality: Interface down")
                        self.set_icon_and_label("network-cellular-offline")
                        self.toggle_item.set_label("Disconnect")
                        self.suspend_item.set_label("Resume")
                        self.suspend_item.set_sensitive(True)
                else:
                    # No IP - still connecting
                    print(f"DEBUG: No IP detected, daemon connecting...")
                    self.status_item.set_label("Status: Connecting...")
                    self.ip_item.set_label("IP: Waiting...")
                    self.quality_item.set_label("Quality: Unknown")
                    self.set_icon_and_label("network-cellular-acquiring")
                    self.toggle_item.set_label("Disconnect")
                    self.suspend_item.set_sensitive(False)
            else:
                # Service not active
                print(f"DEBUG: xmm7360 service not active")

                # Check if status changed
                new_status = "Disconnected"
                if self._last_status != new_status:
                    print(f"DEBUG: Status changed from {self._last_status} to {new_status}, recreating menu")
                    self._last_status = new_status
                    # Recreate entire menu to force update
                    GLib.idle_add(lambda: (self.indicator.set_menu(self.create_menu()), False)[1])

                self.status_item.set_label("Status: Disconnected")
                self.ip_item.set_label("IP: --.--.--.--")
                self.quality_item.set_label("Quality: N/A")
                self.set_icon_and_label("network-cellular-offline")
                self.toggle_item.set_label("Connect")
                self.suspend_item.set_sensitive(False)
                
        except Exception as e:
            print(f"DEBUG: Exception in update_status: {e}")
            self.status_item.set_label("Status: Error")
            self.ip_item.set_label(f"Error: {str(e)[:30]}")
            self.quality_item.set_label("")
            self.set_icon_and_label("dialog-error")

        # Force GTK to process all pending events
        while Gtk.events_pending():
            Gtk.main_iteration()
        
        return True  # Continue updating

    def toggle_connection(self, widget):
        try:
            result = subprocess.run(['systemctl', 'is-active', 'xmm7360'], 
                                    capture_output=True, text=True)
            
            if result.stdout.strip() == 'active':
                # Disconnect LTE
                subprocess.Popen(['sudo', '/usr/local/bin/lte', 'off'])
                self.show_notification("LTE", "Disconnecting... WiFi will be enabled")
                # Re-enable WiFi after disconnect
                GLib.timeout_add_seconds(5, lambda: (self.manage_wifi(True), False)[1])
            else:
                # Connect LTE
                self.show_notification("LTE", "Connecting... WiFi will be disabled (takes 1-2 min)")
                subprocess.Popen(['sudo', '/usr/local/bin/lte', 'on'])
                # Disable WiFi after LTE connects (wait 90 seconds for connection)
                GLib.timeout_add_seconds(90, lambda: (self.manage_wifi(False), False)[1])
        except Exception as e:
            self.show_notification("LTE Error", str(e))

    def toggle_suspend(self, widget):
        try:
            # Check if interface is up
            ip_result = subprocess.run(['ip', 'addr', 'show', 'wwan0'], 
                                      capture_output=True, text=True)
            
            if 'state UP' in ip_result.stdout or 'UP' in ip_result.stdout:
                # Suspend LTE
                result = subprocess.run(['sudo', '/usr/local/bin/lte', 'suspend'],
                                      capture_output=True, text=True)
                print("Suspend output:", result.stdout, result.stderr)
                self.show_notification("LTE", "Suspended - WiFi enabled")
                # Enable WiFi immediately
                self.manage_wifi(True)
                # Update UI immediately
                self.status_item.set_label("Status: Suspended")
                self.suspend_item.set_label("Resume")
                self.set_icon_and_label("network-cellular-offline")
                # Schedule full update
                GLib.timeout_add(100, self.update_status)
            else:
                # Resume LTE
                print("Attempting to resume LTE...")
                
                # Update UI immediately to show resuming
                self.status_item.set_label("Status: Resuming...")
                self.quality_item.set_label("Quality: Connecting...")
                self.suspend_item.set_label("Suspend")
                self.set_icon_and_label("network-cellular-acquiring")
                
                # Actually resume
                result = subprocess.run(['sudo', '/usr/local/bin/lte', 'resume'],
                                      capture_output=True, text=True)
                print("Resume output:", result.stdout)
                
                self.show_notification("LTE", "Resumed - WiFi disabled")
                
                # Disable WiFi immediately
                self.manage_wifi(False)
                
                # Fast updates to catch the connected state
                for delay in [100, 300, 600, 1000, 1500, 2000]:
                    GLib.timeout_add(delay, self.update_status)
                    
        except Exception as e:
            print("Error in toggle_suspend:", str(e))
            self.show_notification("LTE Error", str(e))

    def restart_connection(self, widget):
        subprocess.Popen(['sudo', '/usr/local/bin/lte', 'restart'])
        self.show_notification("LTE", "Restarting... (may take several minutes)")
        # Enable WiFi during restart
        self.manage_wifi(True)
        # Disable WiFi after restart completes (wait 6 minutes for full restart cycle)
        GLib.timeout_add_seconds(360, lambda: (self.manage_wifi(False), False)[1])

    def show_logs(self, widget):
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', 
                         'sudo journalctl -u xmm7360 -f; exec bash'])

    def show_notification(self, title, message):
        try:
            subprocess.run(['notify-send', title, message, '-i', 'network-cellular'])
        except:
            pass

    def quit(self, widget):
        Gtk.main_quit()

if __name__ == "__main__":
    applet = LTEApplet()
    Gtk.main()
