#imports
import os

#enumerator
class Enumerator:
    
    #initializations
    def __init__(self, domain, db, kenzer, github=""):
        self.domain = domain
        self.organization = domain
        self.path = db+self.organization
        self.resources = kenzer+"resources"
        self.githubapi=github
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #core enumerator modules

    #enumerates subdomains
    def subenum(self):
        self.gitdomain()
        self.subfinder()
        self.shuffledns()
        domain = self.domain
        path = self.path
        output =path+"/subenum.kenz"
        if(os.path.exists(output)):
            self.shuffsolv(output, domain)
            os.system("rm {0}".format(output))
        os.system("cat {0}/subfinder.log {0}/subenum.kenz* {0}/shuffledns.log {0}/shuffsolv.log {0}/gitdomain.log | sort -u > {1}".format(path, output))
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates webservers
    def webenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("run portenum for: "+domain)
        output = path+"/httpx.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        self.httpx(subs, output)
        output = path+"/webenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("cat {0}/httpx.log {0}/webenum.kenz* | cut -d' ' -f 1 | sort -u > {1}".format(path, output))
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates additional information for webservers
    def headenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("run webenum for: "+domain)
        output = path+"/headenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        extras = " -status-code -title -web-server -websocket "
        self.httpx(subs, output, extras)
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #enumerates urls
    def urlenum(self):
        self.gau()
        self.giturl()
        domain = self.domain
        path = self.path
        output = path+"/urlenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("cat {0}/urlenum.kenz* {0}/gttpx* {0}/gittpx* | grep '\[200\]' | cut -d' ' -f 1 | sort -u> {1}".format(path, output))
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #enumerates open ports using NXScan
    def portenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+domain)
        self.shuffsolv(subs, domain)
        output = path+"/portenum.kenz"
        subs = path+"/shuffsolv.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("sudo NXScan --only-enumerate -l {0} -o {1}".format(subs,path+"/nxscan"))
        os.system("cat {0}/nxscan/enum.txt {0}/portenum.kenz* | sort -u > {1}".format(path, output))
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #enumerates dns records using DNSX
    def dnsenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+domain)
        output = path+"/dnsenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("dnsx -l {0} -o {1} -a -aaaa -cname -mx -ptr -soa -txt -resp -retry 2".format(subs, output))
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates asn using domlock
    def asnenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+domain)
        output = path+"/asnenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("domlock -l {0} -o {1}".format(subs, output))
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates hidden files & directories using ffuf
    def conenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("run webenum for: "+domain)
        output = path+"/conenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("ffuf -u FuZZDoM/FuZZCoN -w {0}:FuZZDoM,{1}:FuZZCoN -mc 200 -of html -o {2} -t 80".format(subs, self.resources+"/kenzer-templates/ffuf.lst", output))
        if(os.path.exists(output)):
            with open(output) as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #helper modules

    #downloads fresh list of public resolvers
    def getresolvers(self):
        output = self.resources+"/resolvers.txt"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("wget -q https://public-dns.info/nameservers.txt -O {0}".format(output))
    
    def generateSubdomainsWordist(self):
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/internetwache/CT_subdomains/master/top-100000.txt -O top-100000.txt".format(self.resources))
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/cqsd/daily-commonspeak2/master/wordlists/subdomains.txt -O subsB.txt".format(self.resources))
        output = self.resources+"/subsA.txt"
        os.system("cat {0}/top-100000.txt | cut -d ',' -f 2 | sort -u > {1}".format(self.resources, output))
        output = self.resources+"/subdomains.txt"
        os.system("cat {0}/subsA.txt {0}/subsB.txt | sort -u > {1}".format(self.resources, output))
        

    #resolves & removes wildcard subdomains using shuffledns
    def shuffsolv(self, domains, domain):
        self.getresolvers()
        path=self.path
        path+="/shuffsolv.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("shuffledns -strict-wildcard -retries 10 -wt 25 -r {3}/resolvers.txt -o {0} -v -list {1} -d {2}".format(path, domains, domain,self.resources))
        return

    #enumerates subdomains using github-subdomains
    def gitdomain(self):
        domain = self.domain
        path = self.path
        api=self.githubapi
        output = path+"/gitdomain.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("github-subdomains -d {1} -t {2} > {0}".format(output, domain, api))
        return

    #enumerates subdomains using subfinder
    #"retains wildcard domains"
    def subfinder(self):
        domain = self.domain
        path = self.path
        output = path+"/subfinder.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("subfinder -all -recursive -t 50 -max-time 20 -o {0} -v -timeout 20 -d {1}".format(output, domain))
        return

    #enumerates subdomains using shuffledns
    #"removes wildcard domains"
    def shuffledns(self):
        self.getresolvers()
        self.generateSubdomainsWordist()
        domain = self.domain
        path = self.path
        output = path+"/shuffledns.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("shuffledns -retries 10 -strict-wildcard -wt 30 -r {2}/resolvers.txt -w {2}/subdomains.txt -o {0} -v -d {1}".format(output, domain, self.resources))
        self.shuffsolv(output, domain)
        os.system("rm {0} && mv {1} {0}".format(output, path+"/shuffsolv.log"))
        return 

    #probes for web servers using httpx
    def httpx(self, domains, output, extras=""):
        os.system("httpx {2} -no-color -l {0} -threads 100 -retries 2 -timeout 6 -verbose -o {1}".format(domains, output, extras))
        return
    
    #enumerates urls using gau, filters using gf & probes using httpx
    def gau(self):
        domain = self.domain
        path = self.path
        path+="/gau.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("gau -subs -o {0} {1}".format(path, domain))
        out = self.path+"/gauModP.log"
        os.system("cat {0} | gf params | sed 's/=[^&]*/=ALTER/g' | sort -u > {1}".format(path, out))
        inp = out   
        out = self.path+"/gttpxP.log"
        self.httpx(inp, out)
        out = self.path+"/gauModF.log"
        os.system("cat {0} | gf files | sort -u > {1}".format(path, out))
        inp=out
        out = self.path+"/gttpxF.log"
        self.httpx(inp, out)
        return
    
    #enumerates urls using github-endpoints, filters using gf & probes using httpx
    def giturl(self):
        domain = self.domain
        path = self.path
        path+="/giturl.log"
        api = self.githubapi
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("github-endpoints -a -t {2} -d {1} > {0}".format(path, domain, api))
        out = self.path+"/giturlModP.log"
        os.system("cat {0} | gf params | sed 's/=[^&]*/=ALTER/g' | sort -u > {1}".format(path, out))
        inp=out
        out = self.path+"/gittpxP.log"
        self.httpx(inp, out)
        out = self.path+"/giturlModF.log"
        os.system("cat {0} | gf files | sort -u > {1}".format(path, out))
        inp=out
        out = self.path+"/gittpxF.log"
        self.httpx(inp, out)
        return

    #removes log files & empty files
    def remlog(self):
        os.system("rm {0}/*.log*".format(self.path))
        os.system("find {0} -type f -empty -delete".format(self.path))
