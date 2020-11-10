#imports
import os
import tldextract

#monitor
class Monitor:
    
    #initializations
    def __init__(self, domains, db):
        self.domains = domains
        self.organization = "monitor"
        self.db = db
        self.path = db+self.organization
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #core monitor modules
    
    #enumerates subdomains using certex
    def certex(self):
        domains = self.domains
        path = self.path
        output = path+"/subenum.kenz"
        os.system("certex -d {0} -o {1} &".format(domains, output))
        return

    #normalizes enumerations
    def normalize(self):
        self.subenum()
        self.portenum()
        self.webenum()
        self.favscan()
        self.idscan()
        self.cvescan()
        self.vulnscan()
        self.buckscan()
        return

    #normalizes subenum
    def subenum(self):
        kenzerdb = self.db
        subenum = self.path+"/subenum.kenz"
        if(os.path.exists(subenum) == False):
            return
        with open(subenum, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for subdomain in domains:
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/subenum.kenz", 'a') as f:
                    f.write(subdomain)
        return

    #normalizes portenum
    def portenum(self):
        kenzerdb = self.db
        portenum = self.path+"/portenum.kenz"
        if(os.path.exists(portenum) == False):
            return
        with open(portenum, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for subdomain in domains:
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/portenum.kenz", 'a') as f:
                    f.write(subdomain)
        return

    #normalizes webenum
    def webenum(self):
        kenzerdb = self.db
        webenum = self.path+"/webenum.kenz"
        if(os.path.exists(webenum) == False):
            return
        with open(webenum, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for subdomain in domains:
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/webenum.kenz", 'a') as f:
                    f.write(subdomain)
        return
    
    #normalizes favscan
    def favscan(self):
        kenzerdb = self.db
        favscan = self.path+"/favscan.kenz"
        if(os.path.exists(favscan) == False):
            return
        with open(favscan, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            subdomain = data.split("	")[2]
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/favscan.kenz", 'a') as f:
                    f.write(data)
        return
    
    #normalizes idscan
    def idscan(self):
        kenzerdb = self.db
        idscan = self.path+"/idscan.kenz"
        if(os.path.exists(idscan) == False):
            return
        with open(idscan, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            subdomain = data.split(" ")[1]
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/idscan.kenz", 'a') as f:
                    f.write(data)
        return

#normalizes vulnscan
    def vulnscan(self):
        kenzerdb = self.db
        vulnscan = self.path+"/vulnscan.kenz"
        if(os.path.exists(vulnscan) == False):
            return
        with open(vulnscan, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            subdomain = data.split(" ")[1]
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/vulnscan.kenz", 'a') as f:
                    f.write(data)
        return

#normalizes cvescan
    def cvescan(self):
        kenzerdb = self.db
        cvescan = self.path+"/cvescan.kenz"
        if(os.path.exists(cvescan) == False):
            return
        with open(cvescan, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            subdomain = data.split(" ")[1]
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/cvescan.kenz", 'a') as f:
                    f.write(data)
        return

#normalizes buckscan
    def buckscan(self):
        kenzerdb = self.db
        buckscan = self.path+"/buckscan.kenz"
        if(os.path.exists(buckscan) == False):
            return
        with open(buckscan, 'r') as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            subdomain = data.split(" ")[1]
            extracted = tldextract.extract(subdomain)
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            print(domain)
            destination = kenzerdb+domain
            if not os.path.exists(destination):
                os.makedirs(destination)
            with open(destination+"/buckscan.kenz", 'a') as f:
                    f.write(data)
        return