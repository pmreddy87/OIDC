#!/usr/bin/python3
import os
import pypd
import boto3
import logging
import json
import datetime
import smtplib

from botocore.exceptions import ClientError

logger = logging.getLogger()
logging.basicConfig()
logger.setLevel(logging.INFO)
logger.info('Starting...')

alert_method = os.environ['ALERT_METHOD']

def awk_like(instring, index, delimiter=":"):  ### This is an 'awk' like function used to extract data from AWS arns
  try:
    return [instring,instring.split(delimiter)[index-1]][max(0,min(1,index))]
  except:
    return ""


def send_email(host, port, username, password, subject, body, mail_to, mail_from = None, reply_to = None):
    if mail_from is None: mail_from = username
    if reply_to is None: reply_to = mail_to

    message = """From: %s\nTo: %s\nReply-To: %s\nSubject: %s\n\n%s""" % (mail_from, mail_to, reply_to, subject, body)
    print (message)
    try:
        server = smtplib.SMTP(host, port)
        server.ehlo()
        server.starttls()
        server.login(username, password)
        server.sendmail(mail_from, mail_to, message)
        server.close()
        return True
    except Exception as ex:
        print (ex)
        return False

def alert_handler(final_data_array):
    
    logger.info("alert_handler")
    # initialize variables
    username = os.environ['EMAIL_USERNAME'] 
    password = os.environ['EMAIL_TOKEN'] 
    host = os.environ['EMAIL_HOST'] 
    port = os.environ['EMAIL_PORT'] 
    mail_from = os.environ['EMAIL_FROM'] 
    mail_to = os.environ['EMAIL_TO'] 
    origin = os.environ['EMAIL_ORIGIN'] 
    origin_req = "" 
    reply_to = "" 
    subject = "TLS Certificate Expiry Notification" 
    
    body = json.dumps(final_data_array, indent=4)
        
    logger.info("alert_handler_body: %s" % body)
    # vaildate cors access
    cors = ''
    if not origin:
        cors = '*'
    elif origin_req in [o.strip() for o in origin.split(',')]:
        cors = origin_req

    # send mail
    success = False
    # if cors:
    success = send_email(host, port, username, password, subject, body, mail_to, mail_from, reply_to)

### This function creates a json with the details of AWS certificates
def create_json(acm, array_of_arns):
    final_data = []
    # Find the total number of ISSUED certificates
    number_of_certs = len(array_of_arns)
    todays_date = datetime.date.today()
    # Iterate through the AWS ACM certificates and create a detailed json payload of the certificate
    for i in range(number_of_certs):
        data = {}
        r = acm.describe_certificate(CertificateArn=array_of_arns[i])
        expires_on = ((r['Certificate']['NotAfter']).date())
        issued_on = ((r['Certificate']['NotBefore']).date())
        aws_account = awk_like(r['Certificate']['CertificateArn'], 5)
        domain_name = r['Certificate']['DomainName']
        data['AwsAccount'] = aws_account
        data['AwsRegion'] = awk_like(r['Certificate']['CertificateArn'], 4)
        certificate_arn = r['Certificate']['CertificateArn']
        data['CertificateArn'] = certificate_arn
        data['DomainName'] = domain_name
        data['DomainNameAlternatives'] = r['Certificate']['SubjectAlternativeNames']
        data['Status'] = r['Certificate']['Status']
        data['Type'] = r['Certificate']['Type']
        data['RenewalEligibility'] = r['Certificate']['RenewalEligibility']
        data['Issuer'] = r['Certificate']['Issuer']
        data['IssuedOn'] = issued_on.strftime("%Y-%m-%d")
        data['ExpiresOn'] = expires_on.strftime("%Y-%m-%d")
        summarized_message = "Certificate %s is expiring on %s in AWS account: %s" % (domain_name, expires_on, aws_account)
        data['CustomMessage'] = summarized_message
        diff = expires_on - todays_date
        expire_in = diff.days

        ### Set alerts at 60 days, 30 days, 15 days, and every day for week leading up to expiration
        if (expire_in == 60):
            final_data.append(data) #send_notification(data, summarized_message) # data is the full json details, summarized_message is the short tldr message
        elif (expire_in == 30):
            final_data.append(data) #send_notification(data, summarized_message)
        elif (expire_in == 15):
            final_data.append(data) #send_notification(data, summarized_message)
        elif (expire_in == 7):
            final_data.append(data) #send_notification(data, summarized_message)
        elif (expire_in == 1):
            final_data.append(data) #send_notification(data, summarized_message)    
        elif (expire_in <= 400 and expire_in >= 0):
            final_data.append(data) #alert_handler(data, summarized_message)
        elif (expire_in < 0):
            logger.warn("%s has expired %d day(s) ago." % (certificate_arn, expire_in))
        else:
            logger.info("%s will expire in %d day(s)." % (certificate_arn, expire_in))
    
    return final_data

def lambda_handler(event, context):
    # list_of_regions = ['us-east-1','us-west-1']  ### List of regions to check for AWS ACM --
    ### Not currently used but kept in as an option. Use this only if you want to manually maintain a list of specific regions to cycle through
    logger.info("lambda_handler starting...")
    function_arn = str(context.invoked_function_arn)
    default_region = awk_like(function_arn, 4)
    logger.info("functionArn: %s" % function_arn)

    ec2 = boto3.client('ec2', region_name= default_region)  # This is used to lookup available regions
    list_of_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    final_array_data = []
    for x in list_of_regions:
        array_of_arns = []
        acm = boto3.client('acm', region_name=x)
        resp = acm.list_certificates(CertificateStatuses=['ISSUED'])
         

        ### This is used for regions that do not have any imported ACM certificates
        ### If this method is not preferred, you may define a list_of_regions as defined above
        content_length = resp['ResponseMetadata']['HTTPHeaders']['content-length']
        if (int(content_length) < 50):
            logger.info("The response metadata has detected a content-length that indicates that there are no ACM certificates in the current region: %s" % x)
        else:
            ### Iterate through the entire array of arns and do not error if out of range is reached
            try:
                for i in range(99):   ### Maximum range of 99 certificates has been set here for AWS ACM, adjustable if you have more...
                    array_of_arns.append(resp['CertificateSummaryList'][i]['CertificateArn'])
            except IndexError:
                pass

                response_json = create_json(acm,array_of_arns)
                certs_no = len(response_json)
                if(certs_no > 0):
                    for x_json in response_json:
                        final_array_data.append(x_json)

    total_certs = len(final_array_data)
    if(total_certs > 0):    
        alert_handler(final_array_data)
