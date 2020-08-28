

class SYSINFO:

    DATA_STRING = ""

    def __init__(self):
        self.sysinfo = self.get_sys_info()
        self.boot_time = self.get_boot_time()
        self.cpu_info = self.get_cpu_info()
        self.mem_usage = self.get_mem_usage()
        self.disk_info = self.get_disk_info()
        self.net_info  = self.get_net_info()

    def get_size(self, bolter, suffix="B"):
        factor = 1024
        for unit in ["", "K", "M", "G", "T", "P"]:
            if bolter < factor:
                return f"{bolter:.2f}{unit}{suffix}"
            
            bolter /= factor

    def get_sys_info(self):
        headers = ("Platform Tag", "Information")
        values  = []

        uname = platform.uname()

        values.append(("System", uname.system))
        values.append(("Node Name", uname.node))
        values.append(("Release", uname.release))
        values.append(("Version", uname.version))
        values.append(("Machine", uname.machine))
        values.append(("Processor", uname.processor))
        
        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_boot_time(self):
        headers = ("Boot Tags", "Information")
        values  = []

        boot_time_timestamp = psutil.boot_time()
        bt = datetime.fromtimestamp(boot_time_timestamp)

        values.append(("Boot Time", f"{bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"))

        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_cpu_info(self):
        headers = ("CPU Tag", "Value")
        values  = []

        cpufreq = psutil.cpu_freq()

        values.append(("Physical Cores", psutil.cpu_count(logical=False)))
        values.append(("Total Cores", psutil.cpu_count(logical=True)))
        values.append(("Max Frequency", f"{cpufreq.max:.2f}Mhz"))
        values.append(("Min Frequency", f"{cpufreq.min:.2f}Mhz"))
        values.append(("Current Frequency", f"{cpufreq.current:.2f}Mhz"))
        values.append(("CPU Usage", f"{psutil.cpu_percent()}%"))
        
        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_mem_usage(self):
        headers = ("Memory Tag", "Value")
        values  = []

        svmem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        values.append(("Total Mem", f"{self.get_size(svmem.total)}"))
        values.append(("Available Mem", f"{self.get_size(svmem.available)}"))
        values.append(("Used Mem", f"{self.get_size(svmem.used)}"))
        values.append(("Percentage", f"{self.get_size(svmem.percent)}%"))
        
        values.append(("Total Swap", f"{self.get_size(swap.total)}"))
        values.append(("Free Swap", f"{self.get_size(swap.free)}"))
        values.append(("Used Swap", f"{self.get_size(swap.used)}"))
        values.append(("Percentage Swap", f"{self.get_size(swap.percent)}%"))
        
        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_disk_info(self):
        headers = ("Device", "Mountpoint", "File System", "Total Size", "Used", "Free", "Percentage")
        values = []

        partitions = psutil.disk_partitions()

        toappend = []
        for partition in partitions:
            toappend.append(partition.device)
            toappend.append(partition.mountpoint)
            toappend.append(partition.fstype)

            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                toappend.append(self.get_size(partition_usage.total))
                toappend.append(self.get_size(partition_usage.used))
                toappend.append(self.get_size(partition_usage.free))
                toappend.append(self.get_size(partition_usage.percent))
            except PermissionError:
                toappend.append(" "); toappend.append(" "); toappend.append(" "); toappend.append(" "); 
            
            values.append(toappend)
            toappend = []

        rtval = tabulate.tabulate(values, headers=headers)
        return rtval             

    def get_net_info(self):
        headers = ('Interface', 'IP Address', 'MAC Address', 'Netmask', 'Broadcast IP', 'Broadcast MAC')
        values = []

        if_addrs = psutil.net_if_addrs()
        toappend = []

        for interface_name, interface_addresses in if_addrs.items():
            for address in interface_addresses:
                toappend.append(interface_name)
                if str(address.family) == 'AddressFamily.AF_INET':
                    toappend.append(address.address)
                    toappend.append('')
                    toappend.append(address.netmask)
                    toappend.append(address.broadcast)
                elif str(address.family) == 'AddressFamily.AF_PACKET':
                    toappend.append('')
                    toappend.append(address.address)
                    toappend.append(address.netmask)
                    toappend.append('')
                    toappend.append(address.broadcast)
                
                values.append(toappend)
                toappend = []

        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_data(self):
        self.DATA_STRING = "\n" + self.sysinfo + "\n\n" + self.boot_time + "\n\n" + self.cpu_info + "\n\n" + \
                            self.mem_usage + "\n\n" + self.disk_info + "\n\n" + self.net_info + "\n\n"
        return self.DATA_STRING