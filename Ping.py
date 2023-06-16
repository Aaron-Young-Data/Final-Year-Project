import datetime
import ping3
import yagmail
import base64
import time

sender_encoded = "YWFyb255b3VuZ2FsZXJ0QGdtYWlsLmNvbQ=="

path = "Text_Files"
IPfile = "\IPs.txt"
Emailfile = "\Emails.txt"

def fileread(path, file):
    a_file = open(path + file, "r")
    Temp_list = []
    for line in a_file:
        stripped_line = line.strip()
        line_list = stripped_line.split()
        Temp_list.append(line_list)
    a_file.close()
    return(Temp_list)

def decode(encoded):
    bytes = encoded.encode('ascii')
    bytes = base64.b64decode(bytes)
    return(bytes.decode('ascii'))

yag = yagmail.SMTP(decode(sender_encoded), oauth2_file="oath2_creds.json")

while True:
    ip_list = fileread(path, IPfile)
    Email_list = fileread(path, Emailfile)
    for a in ip_list:
        r = ping3.ping(a[0])
        print(a[0])
        if r == False:
            print("Failed")
            nowtime = datetime.datetime.now()
            body = ("IP: " + str(a[0]) + """
            Currently unreacheable.
            Time: """ + str(nowtime))
            subject = ("Alert! IP: " + str(a[0]))
            for b in Email_list:
                #try:
                    yag.send(
                        to=(b[0]),
                        subject=str(subject),
                        contents=str(body)
                    )
                    print("Email Sent to:", b[0])
                #except:
                #    print("Email Failed to Send")

        else:
            print("Success")
    time.sleep(3600)
