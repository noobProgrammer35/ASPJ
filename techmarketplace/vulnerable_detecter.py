from email.mime.text import MIMEText
import subprocess
import importlib
import vulners
import pkg_resources
import pipreqs
import outdated
import smtplib


def run_command():
    vulners_api = vulners.Vulners(api_key="KDSGZ618GWT2F5JO1EEU4R5K87GR9987FQQZDNQF0K0RW3VK5DJ7OUI305S7PQME")
    # generate current verison of package
    try:
        torch_loader = importlib.import_module('pipreqs')
    except:
        subprocess.call('pip3 install pipreqs')
        torch_loader = importlib.import_module('pipreqs')

    vul_dict = {}
    if torch_loader:
        subprocess.call('pipreqs --force')

    test = []
    count = 0
    with open('requirements.txt','r') as f:
            for line in f:
                test.append(line)
                array=line.strip().split('==')
                results = vulners_api.softwareVulnerabilities(array[0].replace('_','-'),array[1]) # pass in package and verison
                is_outdated, latest_version = outdated.check_outdated(array[0].replace('_','-'), array[1])
                if results:
                    Message =  " " +  results['software'][0]['description'] + results['software'][0]['title']
                    if is_outdated:
                        Message += 'Your current version is {0}. Please upgrade to {1}. Changes has been made in requirement file: Changed {2} to {3}'.format(array[1],latest_version,array[1],latest_version)
                        test[count] = array[0]+"=="+latest_version+"\n"
                    info = {'Message':Message,'Current_Version':array[1],'Latest_Version':latest_version}
                    vul_dict[array[0]] = info
                    print(vul_dict)
                count+=1

    # changing old version to new version in requirements.txt
    with open('requirements.txt','w') as f:
        f.writelines(test)

    if vul_dict:
        message = ''
        for key in vul_dict:
            message += 'Package:{0}\nCurrent Version:{1}\nLatest Version:{2}\nVulnerability Detected:{3}\n\n'.format(key,vul_dict[key]['Current_Version'],vul_dict[key]['Latest_Version'],vul_dict[key]['Message'])
        construct_email(message)
    else:
        message ='Good Job! No vulnerability detected.'
        construct_email(message)


def construct_email(message):
    msg = MIMEText(message)
    msg['Subject'] = 'Dependency Check Result'
    msg['From'] = 'piethonlee123@gmail.com'
    msg['To'] = 'piethonlee123@gmail.com'
    send_email(msg)


def send_email(message):
    smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
    smtpObj.ehlo()
    smtpObj.starttls()
    smtpObj.ehlo()
    smtpObj.login('piethonlee123@gmail.com', 'ASPJPYTHON123')
    smtpObj.sendmail('piethonlee123@gmail.com','piethonlee123@gmail.com',message.as_string())

run_command()
