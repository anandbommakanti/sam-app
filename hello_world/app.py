import os
import sys
import json
import boto3
import traceback
import random
import psycopg2
import uuid
from datetime import datetime, timezone, date
import pytz
import logging
import warnings
import base64
from botocore.exceptions import ClientError

warnings.filterwarnings("ignore")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


TABLE_NAME = "end_user"
OTP_GEN_PATH = "/otp-gen"
NEW_USER_REG_PATH = "/new-registration"
API_NAME = "eu-app-otp"


"""

OTP generation scenario : 

User opens the app and enters the mobile number - FE person calls otp generation api
If user is already registered -> the api generates otp and gives token as registered
If user is not registered -> the api generates otp and gives token as not_registered -> then the FE 
person calls register_new_user api


New User Registration scenario:

After successful otp verification, If user is not registered, FE page will be redirected to
collect fullname & email details. So new registration method will be used to details in db.    

"""
def set_environment_config(env_name):
    global secret_name
    global region_name
    """ Set the Prod or Dev Environment Config """
    if env_name == "prod":
    
        secret_name= "rds-prod-secrets"
        region_name = "ap-south-1"
    else: # dev
        secret_name = "rds-dev-secrets"
        region_name = "ap-south-1"


def get_db_secret():
    """ Create a Secrets Manager client """
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        logger.info("Get the RDS Details from Secret Manager Service...")
    except ClientError as e:
        logger.info("Error at get_secret function: {}".format(e))
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return json.loads(decoded_binary_secret)


def rds_connection(rds_config):
    """ RDS Connection """
    rds_host = rds_config["host"]
    username = rds_config["username"]
    password = rds_config["password"]
    db_name = rds_config["dbname"]
    port = rds_config["port"]

    connection = None
    try:
        conn_string = "host=%s user=%s password=%s dbname=%s port=%s" % (rds_host, username, password, db_name, port)
        connection = psycopg2.connect(conn_string)
        logger.info("RDS Connection Established...")
    except (Exception, psycopg2.Error) as error:
        logger.info("Error while connecting to Postgres SQL", error)
        connection.close()
        logger.info("RDS Connection is closed...")
    return connection

def ia_ingestion(cursor,method,status,err):
    """ Inter audit variables"""
    dt = datetime.now(pytz.timezone("Asia/Kolkata"))
    internal_audit_id = "BM-" + str(dt.strftime('%y') + dt.strftime('%m') + dt.strftime('%d')) + "-IA-" + str(
        dt.strftime("%H:%M:%S:%f").replace(':', ''))

    cursor.execute(
            """INSERT INTO internal_audit (internal_audit_id, method, status, error, api_name,
            ingestion_date_time) VALUES (%s, %s, %s, %s, %s, %s)""",
            (internal_audit_id, method, status, str(err), API_NAME, dt.now()))


def otp_generation(_body, cursor):
    mobile_number = _body["phone"]
    otp = random.randint(100000, 999999)
    sns = boto3.client("sns")
    message = str("BYME OTP for mobile number verification of " + str(mobile_number) + " is " + str(otp))
    number = str("+91"+mobile_number)
    try:
        response = sns.publish(PhoneNumber=number, Message=message)
        cursor.execute("SELECT user_id, phone_number, full_name FROM {} WHERE phone_number = '{}'".format(TABLE_NAME, mobile_number))
        value = cursor.fetchone()
        if value:
            logger.info("Mobile number checked in database...")
            logger.info("Generating 6 digit OTP for given mobile number " + mobile_number)
            logger.info("User already exists")
            dt = datetime.now(pytz.timezone('Asia/Kolkata'))
            cursor.execute("UPDATE {} SET otp = '{}', last_login = '{}' WHERE phone_number = '{}'".format(TABLE_NAME, otp, dt, mobile_number))        
            payload = {"mobile_number": mobile_number, "otp": otp, "user_id": str(value[0]), "full_name": str(value[2]), "token": "registered"}
        else:
            logger.info("Generating 6 digit OTP for given mobile number " + mobile_number)
            logger.info("User doesn't exists, create new user") 
            payload = {"mobile_number": mobile_number, "otp": otp, "token": "not_registered"}
    except Exception as err:
        logger.info("Error in otp_generation : {}".format(err))
        ia_ingestion(cursor,OTP_GEN_PATH,"Failed",err)
        payload = {"error":"Error in otp_generation"}
    return payload
    

def register_new_user(_body, cursor):
    mobile_number = _body["phone"]
    full_name = _body["full_name"]
    email_id = _body["email_id"]
    dt = datetime.now(pytz.timezone('Asia/Kolkata'))
    unique_id = str(uuid.uuid4())
    random_numbers = random.randint(1000, 9999)
    year = str(date.today().year)
    year = year[-2:]
    try:
        user_id_value = str(full_name[0:3] + mobile_number[-3:] + str(year) + "-" +
                            str(random_numbers) + "-" + unique_id[0:4])
        user_id_value = user_id_value.upper()
        cursor.execute("SELECT phone_number, user_id FROM {} WHERE phone_number = '{}'".format(TABLE_NAME, mobile_number))
        check_mobile_number = cursor.fetchone()
        if check_mobile_number is None:
            cursor.execute(
                """INSERT INTO end_user (user_id, phone_number, full_name, email_id, last_login, 
                register_date_time, gender, age) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (user_id_value, mobile_number, full_name.title(), email_id, dt.now(), dt.now(), "-", "0"))
            payload = {"user_id": user_id_value, "token": "registered", "full_name": full_name}
        else:
            payload = {"user_id": check_mobile_number[1], "token": "mobile_number_exists", "full_name":full_name}
    except Exception as err:
        logger.info("Error in register_new_user : {}".format(err))
        ia_ingestion(cursor,NEW_USER_REG_PATH,"Failed",err)
        payload = {"error":"Error in register_new_user"}
    return payload


def lambda_handler(event, context):
    """ Main Function """
    operation = event["requestContext"]["resourcePath"]
    _body = json.loads(event["body"])
    mobile_number = _body["phone"]
    print(_body)

    """Set environment details"""
    env_name = _body["environment"]
    set_environment_config(env_name)

    """ Get DB Secrets """
    secret_json = get_db_secret()
    """ RDS Connection """
    conn = rds_connection(secret_json)
    cursor = conn.cursor()

    try:
        if operation == OTP_GEN_PATH:
            payload = otp_generation(_body, cursor)
            conn.commit()
            logger.info("1. done" + str(payload))

        elif operation == NEW_USER_REG_PATH:
            payload = register_new_user(_body, cursor)
            conn.commit()
            logger.info("2. done" + str(payload))

        return {
            "statusCode": 200,
            "body": json.dumps(payload)
        }

    except Exception as e:
        logger.info("OTP generation failed " + str(repr(e)))
        err_obj = sys.exc_info()
        logger.info(str(err_obj))
        logger.info(str(traceback.print_exc()))
        payload = {"mobile_number": mobile_number, "otp": "failed"}
        ia_ingestion(cursor,"Eception 500","Failed",err_obj)
        conn.commit()
        
        return {
            "statusCode": 500,
            "body": json.dumps(payload)
        }

    finally:
        if conn:
            cursor.close()
            conn.close()
            logger.info("RDS connection is closed")


# if __name__ == '__main__':
#     print('Start.....')
#     # event = {'resource': OTP_GEN_PATH, 'path': OTP_GEN_PATH, 'httpMethod': 'POST',
#     #          'headers': {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br', 'CloudFront-Forwarded-Proto': 'https',
#     #                      'CloudFront-Is-Desktop-Viewer': 'true', 'CloudFront-Is-Mobile-Viewer': 'false',
#     #                      'CloudFront-Is-SmartTV-Viewer': 'false', 'CloudFront-Is-Tablet-Viewer': 'false',
#     #                      'CloudFront-Viewer-Country': 'IN', 'Content-Type': 'application/json', 'Host': 'x1fn5sxnfe.execute-api.ap-south-1.amazonaws.com', 'Postman-Token': 'f7b55f56-3eb8-49ab-a248-f88f295ecdfa', 'User-Agent': 'PostmanRuntime/7.29.0', 'Via': '1.1 63fb8e55a5b4004c4539c5ce22956da8.cloudfront.net (CloudFront)', 'X-Amz-Cf-Id': 'guLWEStLU61FGuemnuDXU3dsin3RpZxm6CsIFW2BBkeUy2DUlWmPgw==',
#     #                      'X-Amzn-Trace-Id': 'Root=1-621e03e7-71884758593a96c72c06abd6', 'X-Forwarded-For': '223.228.113.141, 64.252.191.87', 'X-Forwarded-Port': '443', 'X-Forwarded-Proto': 'https'}, 'multiValueHeaders': {'Accept': ['*/*'], 'Accept-Encoding': ['gzip, deflate, br'], 'CloudFront-Forwarded-Proto': ['https'], 'CloudFront-Is-Desktop-Viewer': ['true'],
#     #                      'CloudFront-Is-Mobile-Viewer': ['false'], 'CloudFront-Is-SmartTV-Viewer': ['false'], 'CloudFront-Is-Tablet-Viewer': ['false'], 'CloudFront-Viewer-Country': ['IN'], 'Content-Type': ['application/json'], 'Host': ['x1fn5sxnfe.execute-api.ap-south-1.amazonaws.com'], 'Postman-Token': ['f7b55f56-3eb8-49ab-a248-f88f295ecdfa'],
#     #                      'User-Agent': ['PostmanRuntime/7.29.0'], 'Via': ['1.1 63fb8e55a5b4004c4539c5ce22956da8.cloudfront.net (CloudFront)'],
#     #                      'X-Amz-Cf-Id': ['guLWEStLU61FGuemnuDXU3dsin3RpZxm6CsIFW2BBkeUy2DUlWmPgw=='], 'X-Amzn-Trace-Id': ['Root=1-621e03e7-71884758593a96c72c06abd6'],
#     #                      'X-Forwarded-For': ['223.228.113.141, 64.252.191.87'], 'X-Forwarded-Port': ['443'], 'X-Forwarded-Proto': ['https']}, 'queryStringParameters': None, 'multiValueQueryStringParameters': None, 'pathParameters': None,
#     #                     'stageVariables': None, 'requestContext': {'resourceId': '43lg0c', 'resourcePath': OTP_GEN_PATH,
#     #                    'httpMethod': 'POST', 'extendedRequestId': 'OTWMRGzphcwFRlw=', 'requestTime': '01/Mar/2022:11:30:47 +0000', 'path': '/Stage/otpposts', 'accountId': '151669786655', 'protocol': 'HTTP/1.1', 'stage': 'Stage', 'domainPrefix': 'x1fn5sxnfe', 'requestTimeEpoch': 1646134247982, 'requestId': 'f5a9858e-51c2-444b-9aed-a9a6a98677b1', 'identity': {'cognitoIdentityPoolId': None, 'accountId': None, 'cognitoIdentityId': None, 'caller': None, 'sourceIp': '223.228.113.141', 'principalOrgId': None, 'accessKey': None, 'cognitoAuthenticationType': None, 'cognitoAuthenticationProvider': None, 'userArn': None, 'userAgent': 'PostmanRuntime/7.29.0', 'user': None}, 'domainName': 'x1fn5sxnfe.execute-api.ap-south-1.amazonaws.com', 'apiId': 'x1fn5sxnfe'},
#     #          'body': '{ "phone": "9967630937", "full_name":"Ranjith", "email_id":"ranjith@v.in"}', 'isBase64Encoded': False,
#     #          }
#     event = {'resource': NEW_USER_REG_PATH, 'path': NEW_USER_REG_PATH, 'httpMethod': 'POST',
#              'headers': {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br', 'CloudFront-Forwarded-Proto': 'https',
#                          'CloudFront-Is-Desktop-Viewer': 'true', 'CloudFront-Is-Mobile-Viewer': 'false',
#                          'CloudFront-Is-SmartTV-Viewer': 'false', 'CloudFront-Is-Tablet-Viewer': 'false',
#                          'CloudFront-Viewer-Country': 'IN', 'Content-Type': 'application/json', 'Host': 'x1fn5sxnfe.execute-api.ap-south-1.amazonaws.com', 'Postman-Token': 'f7b55f56-3eb8-49ab-a248-f88f295ecdfa', 'User-Agent': 'PostmanRuntime/7.29.0', 'Via': '1.1 63fb8e55a5b4004c4539c5ce22956da8.cloudfront.net (CloudFront)', 'X-Amz-Cf-Id': 'guLWEStLU61FGuemnuDXU3dsin3RpZxm6CsIFW2BBkeUy2DUlWmPgw==',
#                          'X-Amzn-Trace-Id': 'Root=1-621e03e7-71884758593a96c72c06abd6', 'X-Forwarded-For': '223.228.113.141, 64.252.191.87', 'X-Forwarded-Port': '443', 'X-Forwarded-Proto': 'https'}, 'multiValueHeaders': {'Accept': ['*/*'], 'Accept-Encoding': ['gzip, deflate, br'], 'CloudFront-Forwarded-Proto': ['https'], 'CloudFront-Is-Desktop-Viewer': ['true'],
#                          'CloudFront-Is-Mobile-Viewer': ['false'], 'CloudFront-Is-SmartTV-Viewer': ['false'], 'CloudFront-Is-Tablet-Viewer': ['false'], 'CloudFront-Viewer-Country': ['IN'], 'Content-Type': ['application/json'], 'Host': ['x1fn5sxnfe.execute-api.ap-south-1.amazonaws.com'], 'Postman-Token': ['f7b55f56-3eb8-49ab-a248-f88f295ecdfa'],
#                          'User-Agent': ['PostmanRuntime/7.29.0'], 'Via': ['1.1 63fb8e55a5b4004c4539c5ce22956da8.cloudfront.net (CloudFront)'],
#                          'X-Amz-Cf-Id': ['guLWEStLU61FGuemnuDXU3dsin3RpZxm6CsIFW2BBkeUy2DUlWmPgw=='], 'X-Amzn-Trace-Id': ['Root=1-621e03e7-71884758593a96c72c06abd6'],
#                          'X-Forwarded-For': ['223.228.113.141, 64.252.191.87'], 'X-Forwarded-Port': ['443'], 'X-Forwarded-Proto': ['https']}, 'queryStringParameters': None, 'multiValueQueryStringParameters': None, 'pathParameters': None,
#                         'stageVariables': None, 'requestContext': {'resourceId': '43lg0c', 'resourcePath': NEW_USER_REG_PATH,
#                        'httpMethod': 'POST', 'extendedRequestId': 'OTWMRGzphcwFRlw=', 'requestTime': '01/Mar/2022:11:30:47 +0000', 'path': '/Stage/otpposts', 'accountId': '151669786655', 'protocol': 'HTTP/1.1', 'stage': 'Stage', 'domainPrefix': 'x1fn5sxnfe', 'requestTimeEpoch': 1646134247982, 'requestId': 'f5a9858e-51c2-444b-9aed-a9a6a98677b1', 'identity': {'cognitoIdentityPoolId': None, 'accountId': None, 'cognitoIdentityId': None, 'caller': None, 'sourceIp': '223.228.113.141', 'principalOrgId': None, 'accessKey': None, 'cognitoAuthenticationType': None, 'cognitoAuthenticationProvider': None, 'userArn': None, 'userAgent': 'PostmanRuntime/7.29.0', 'user': None}, 'domainName': 'x1fn5sxnfe.execute-api.ap-south-1.amazonaws.com', 'apiId': 'x1fn5sxnfe'},
#              'body': '{ "phone": "8881888123", "full_name":"ramesh prasad", "email_id":"ramesh@gmail.com"}', 'isBase64Encoded': False,
#              }

#     context = ""
#     print(lambda_handler(event, context))
#     print('End.....')
