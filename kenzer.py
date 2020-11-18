#imports
import zulip
import time
import os
import sys
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
from configparser import ConfigParser
import validators

#core modules
from modules import enumerator
from modules import scanner
from modules import monitor

#colors
BLUE='\033[94m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CLEAR='\x1b[0m'

#configs
try:
    conf = "configs/kenzer.conf"
    config = ConfigParser()
    with open(conf) as f:
         config.read_file(f, conf)
    _BotMail=config.get("kenzer", "email")
    _Site=config.get("kenzer", "site")
    _APIKey=config.get("kenzer", "key")
    _uploads=config.get("kenzer", "uploads")
    _subscribe=config.get("kenzer", "subscribe")
    _kenzer=config.get("kenzer", "path")
    _kenzerdb=config.get("kenzerdb", "path")
    _github=config.get("kenzerdb", "token")
    _repo=config.get("kenzerdb", "repo")
    _user=config.get("kenzerdb", "user")
    _home=config.get("env", "home")
    os.chdir(_kenzer)
    os.environ["HOME"] = _home
    if(os.path.exists(_kenzerdb) == False):
        os.system("mkdir "+_kenzerdb)
except:
    sys.exit(RED+"[!] invalid configurations"+CLEAR)

#kenzer 
class Kenzer(object):
    
    #initializations
    def __init__(self):
        print(BLUE+"KENZER[3.02] by ARPSyndicate"+CLEAR)
        print(YELLOW+"automated web assets enumeration & scanning"+CLEAR)
        self.client = zulip.Client(email=_BotMail, site=_Site, api_key=_APIKey)
        self.upload=False
        if _subscribe=="True":
            self.subscribe()
            print(YELLOW+"[*] subscribed all streams"+CLEAR)    
        if _uploads=="True":
            self.upload=True
            print(YELLOW+"[*] enabled uploads"+CLEAR)
        print(YELLOW+"[*] training chatterbot"+CLEAR)
        self.chatbot = ChatBot("Kenzer")
        self.trainer = ChatterBotCorpusTrainer(self.chatbot)
        time.sleep(3)
        self.trainer.train("chatterbot.corpus.english")
        time.sleep(3)
        self.modules=["monitor", "subenum", "webenum", "conenum", "dnsenum", "portenum", "asnenum", "urlenum", "favscan", "cscan", "idscan", "subscan", "cvescan", "vulnscan", "portscan", "parascan", "endscan", "buckscan", "vizscan", "enum", "scan", "recon", "hunt", "remlog", "sync"]
        print(YELLOW+"[*] KENZER is online"+CLEAR)
        print(YELLOW+"[*] {0} modules up & running".format(len(self.modules))+CLEAR)

    #subscribes to all streams
    def subscribe(self):
        try:
            json=self.client.get_streams()["streams"]
            streams=[{"name":stream["name"]} for stream in json]
            self.client.add_subscriptions(streams)
        except:
            print(RED+"[!] an exception occurred.... retrying...."+CLEAR)
            self.subscribe()

    #manual
    def man(self):
        message = "**KENZER[3.02]**\n"
        message +="**KENZER modules**\n"
        message +="  `subenum` - enumerates subdomains\n"
        message +="  `webenum` - enumerates webservers\n"
        message +="  `conenum` - enumerates hidden files & directories\n"
        message +="  `portenum` - enumerates open ports\n"
        message +="  `dnsenum` - enumerates dns records\n"
        message +="  `asnenum` - enumerates asn\n"
        message +="  `urlenum` - enumerates urls\n"
        message +="  `subscan` - hunts for subdomain takeovers\n"
        message +="  `cscan` - scan with customized templates\n"
        message +="  `cvescan` - hunts for CVEs\n"
        message +="  `vulnscan` - hunts for other common vulnerabilites\n"
        message +="  `portscan` - scans open ports\n"
        message +="  `parascan` - hunts for vulnerable parameters\n"
        message +="  `endscan` - hunts for vulnerable endpoints\n"
        message +="  `buckscan` - hunts for unreferenced aws s3 buckets\n"
        message +="  `favscan` - fingerprints webservers using favicon\n"
        message +="  `idscan` - identifies applications running on webservers\n"
        message +="  `vizscan` - screenshots applications running on webservers\n"
        message +="  `enum` - runs all enumerator modules\n"
        message +="  `scan` - runs all scanner modules\n"
        message +="  `recon` - runs all modules\n"
        message +="  `hunt` - runs your custom workflow\n"
        message +="  `remlog` - removes log files\n"
        message +="  `upload` - switches upload functionality\n"
        message +="  `sync` - synchronizes the local kenzerdb with github\n"
        message +="  `upgrade` - upgrades kenzer to latest version\n"
        message +="  `monitor` - monitors ct logs for new subdomains\n"
        message +="  `monitor normalize` - normalizes the enumerations from ct logs\n"
        message +="`kenzer <module>` - runs a specific modules\n"
        message +="`kenzer man` - shows this manual\n"
        message +="or you can just interact with chatterbot\n"
        self.sendMessage(message)
        return

    #sends messages
    def sendMessage(self, message):
        time.sleep(2)
        if self.type == "private":
            self.client.send_message({
                "type": self.type,
                "to": self.sender_email,
                "content": message
            })
        else:
            self.client.send_message({
                "type": self.type,
                "subject": self.subject,
                "to": self.display_recipient,
                "content": message
            })
        time.sleep(3)
        return

    #uploads output
    def uploader(self, domain, raw):
        global _kenzerdb
        global _Site
        org=domain
        data = _kenzerdb+org+"/"+raw
        print(data)
        if(os.path.exists(data) == False):
            return
        with open(data, 'rb') as fp:
            uploaded = self.client.call_endpoint(
            'user_uploads',
            method='POST',
            files=[fp],
        )
        self.sendMessage("{0}/{1} : {3}{2}".format(org, raw, uploaded['uri'], _Site))
        print(uploaded)

    #monitors ct logs
    def monitor(self):
        self.sendMessage("started monitoring")
        self.monitor = monitor.Monitor(" ".join(self.content[2:]), _kenzerdb)
        self.monitor.certex()
        return

    #normalizes enumerations from ct logs
    def normalize(self):
        self.monitor = monitor.Monitor(" ".join(self.content[2:]), _kenzerdb)
        self.monitor.normalize()
        self.sendMessage("normalized successfully")
        return

    #enumerates subdomains
    def subenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started subenum for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer, _github)
            message = self.enum.subenum()
            self.sendMessage(message)
            if self.upload:
                file = "subenum.kenz"
                self.uploader(self.content[i], file)
        return

    #probes web servers from enumerated subdomains
    def webenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started webenum for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.webenum()
            self.sendMessage(message)
            if self.upload:
                file = "webenum.kenz"
                self.uploader(self.content[i], file)
        return
    
    #enumerates dns records
    def dnsenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started dnsenum for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.dnsenum()
            self.sendMessage(message)
            if self.upload:
                file = "dnsenum.kenz"
                self.uploader(self.content[i], file)
        return

    #enumerates hidden files & directories
    def conenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started conenum for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.conenum()
            self.sendMessage(message)
            if self.upload:
                file = "conenum.kenz"
                self.uploader(self.content[i], file)
        return
    
    #enumerates asn for enumerated subdomains
    def asnenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started asnenum for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.asnenum()
            self.sendMessage(message)
            if self.upload:
                file = "asnenum.kenz"
                self.uploader(self.content[i], file)
        return
    
    #enumerates open ports
    def portenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started portenum for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.enum.portenum()
            self.sendMessage(message)
            if self.upload:
                file = "portenum.kenz"
                self.uploader(self.content[i], file)
        return

    #enumerates urls
    def urlenum(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started urlenum for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _kenzer, _github)
            message = self.enum.urlenum()
            self.sendMessage(message)
            if self.upload:
                file = "urlenum.kenz"
                self.uploader(self.content[i], file)
        return

    #hunts for subdomain takeovers
    def subscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started subscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.subscan()
            self.sendMessage(message)
            if self.upload:
                file = "subscan.kenz"
                self.uploader(self.content[i], file)

        return

    #scans with customized templates
    def cscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started cscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.cscan()
            self.sendMessage(message)
            if self.upload:
                file = "cscan.kenz"
                self.uploader(self.content[i], file)

        return
        
    #hunts for CVEs
    def cvescan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started cvescan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.cvescan()
            self.sendMessage(message)
            if self.upload:
                file = "cvescan.kenz"
                self.uploader(self.content[i], file)

        return
    
    #hunts for other common vulnerabilities
    def vulnscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started vulnscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.vulnscan()
            self.sendMessage(message)
            if self.upload:
                file = "vulnscan.kenz"
                self.uploader(self.content[i], file)

        return
    #scans open ports
    def portscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started portscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.portscan()
            self.sendMessage(message)
            if self.upload:
                file = "portscan.kenz"
                self.uploader(self.content[i], file)
        return
    
    #hunts for vulnerable parameters
    def parascan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started parascan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.parascan()
            self.sendMessage(message)
            if self.upload:
                file = "parascan.kenz"
                self.uploader(self.content[i], file)

        return
    
    #hunts for vulnerable endpoints
    def endscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started endscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.endscan()
            self.sendMessage(message)
            if self.upload:
                file = "endscan.kenz"
                self.uploader(self.content[i], file)

        return
    
    #hunts for subdomain takeovers
    def buckscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started buckscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.buckscan()
            self.sendMessage(message)
            if self.upload:
                file = "buckscan.kenz"
                self.uploader(self.content[i], file)

        return

    #fingerprints servers using favicons
    def favscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started favscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.favscan()
            self.sendMessage(message)
            if self.upload:
                file = "favscan.kenz"
                self.uploader(self.content[i], file)
        return
    
    #identifies applications running on webservers
    def idscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started idscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.idscan()
            self.sendMessage(message)
            if self.upload:
                file = "idscan.kenz"
                self.uploader(self.content[i], file)
        return
    
    #screenshots applications running on webservers
    def vizscan(self):
        for i in range(2,len(self.content)):
            self.sendMessage("started vizscan for: "+self.content[i].lower())
            if(validators.domain(self.content[i].lower())!= True and self.content[i].lower() != "monitor"):
                self.sendMessage("invalid domain !!!")
                continue
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.vizscan()
            self.sendMessage(message)
            if self.upload:
                for file in os.listdir(_kenzerdb+self.content[i].lower()+"/aquatone/screenshots/"):

                    self.uploader(self.content[i], "aquatone/screenshots/"+file)
        return

    #runs all enumeration modules
    def enum(self):
        self.subenum()
        self.portenum()
        self.webenum()
        self.dnsenum()
        self.conenum()
        self.asnenum()
        #experimental ones
        #self.urlenum()
        return

    #runs all scanning modules
    def scan(self):
        self.favscan()
        self.idscan()
        self.subscan()
        self.portscan()
        self.buckscan()
        self.cvescan()
        self.vulnscan()
        self.vizscan()
        #experimental ones
        #self.parascan()
        #self.endscan()
        return

    #define your custom workflow    
    def hunt(self):
        self.subenum()
        self.portenum()
        self.webenum()
        self.dnsenum()
        self.conenum()
        self.subscan()
        self.idscan()
        self.favscan()
        self.buckscan()
        self.portscan()
        self.cvescan()
        self.vulnscan()
        self.asnenum()
        self.vizscan()
        #experimental ones
        #self.urlenum()
        #self.parascan()
        #self.endscan()
        #self.remlog()
        return

    #runs all modules
    def recon(self):
        self.enum()
        self.scan()
        return
    
    #synchronizes the local kenzerdb with github
    def sync(self):
        os.system("cd {0} && git remote set-url origin https://{1}@github.com/{2}/{3}.git && git pull && git add . && git commit -m updated && git push".format(_kenzerdb, _github, _user, _repo))
        self.sendMessage("sync complete")
        return
    
    #upgrades kenzer to latest version
    def upgrade(self):
        os.system("bash update.sh")
        self.sendMessage("upgrade completed")
        return

    #removes old log files
    def remlog(self):
        for i in range(2,len(self.content)):
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb)
            message = self.enum.remlog()
            self.sendMessage(message)
        return

    #controls
    def process(self, text):
        self.content = text["content"].split()
        self.sender_email = text["sender_email"]
        self.type = text["type"]
        self.display_recipient = text['display_recipient']
        self.subject = text['subject']
        content=self.content
        print(content)
        if self.sender_email == _BotMail:
            return
        try:
            if len(content)>1 and content[0].lower() == "@**{0}**".format(_BotMail.split('@')[0].replace("-bot","")):
                if content[1].lower() == "man":
                    if len(content)==2:
                        self.man()
                    else:
                        message = "excuse me???"
                        self.sendMessage(message)
                elif content[1].lower() == "monitor":
                    if content[2].lower() == "normalize":
                        self.normalize()
                    else:
                        self.monitor()    
                elif content[1].lower() == "subenum":
                    self.subenum()
                elif content[1].lower() == "webenum":
                    self.webenum()
                elif content[1].lower() == "asnenum":
                    self.asnenum()
                elif content[1].lower() == "dnsenum":
                    self.dnsenum()
                elif content[1].lower() == "conenum":
                    self.conenum()
                elif content[1].lower() == "favscan":
                    self.favscan()
                elif content[1].lower() == "portenum":
                    self.portenum()
                elif content[1].lower() == "urlenum":
                    self.urlenum()
                elif content[1].lower() == "subscan":
                    self.subscan()
                elif content[1].lower() == "cscan":
                    self.cscan()
                elif content[1].lower() == "cvescan":
                    self.cvescan()
                elif content[1].lower() == "vulnscan":
                    self.vulnscan()
                elif content[1].lower() == "portscan":
                    self.portscan()
                elif content[1].lower() == "parascan":
                    self.parascan()
                elif content[1].lower() == "endscan":
                    self.endscan()
                elif content[1].lower() == "idscan":
                    self.idscan()
                elif content[1].lower() == "vizscan":
                    self.vizscan()
                elif content[1].lower() == "buckscan":
                    self.buckscan()
                elif content[1].lower() == "enum":
                    self.enum()
                elif content[1].lower() == "scan":
                    self.scan()
                elif content[1].lower() == "hunt":
                    self.hunt()
                elif content[1].lower() == "recon":
                    self.recon()
                elif content[1].lower() == "remlog":
                    self.remlog()
                elif content[1].lower() == "sync":
                    self.sync()
                elif content[1].lower() == "upgrade":
                    self.upgrade()
                elif content[1].lower() == "upload":
                    self.upload = not self.upload
                    self.sendMessage("upload: "+str(self.upload))
                else:
                    message = self.chatbot.get_response(' '.join(self.content))
                    message = message.serialize()['text']
                    self.sendMessage(message)
        except Exception as exception:
            self.sendMessage("Exception: {}".format(type(exception).__name__))
        return    

#main
def main():
    bot = Kenzer()
    bot.client.call_on_each_message(bot.process)

#runs main
if __name__ == "__main__":
    main()
