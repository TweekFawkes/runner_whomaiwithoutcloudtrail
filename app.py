import os

import time
import logging
import requests
from requests_aws4auth import AWS4Auth
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

import base64
import binascii

def AwsUsername_from_AwsCreds(sAwsAccessKeyId, sAwsSecretAccessKey):
    try:
        sReturn = "E55OR"
        
        # Request details
        region = 'us-east-1'
        service = 'sqs'
        url = 'https://sqs.us-east-1.amazonaws.com/'
        payload = {'Action': 'ListQueues'}
        
        # Create AWS4Auth instance
        auth = AWS4Auth(sAwsAccessKeyId, sAwsSecretAccessKey, region, service)
        
        # Custom User-Agent string
        sUserAgent = "Boto3/1.17.46 Python/3.6.14 Linux/4.14.238-182.422.amzn2.x86_64 exec-env/AWS_ECS_FARGATE Botocore/1.20.46"

        # Create headers dictionary with custom User-Agent
        headers = {
            "User-Agent": sUserAgent
        }

        # Make the request
        response = requests.post(url, auth=auth, params=payload, headers=headers)
        response.raise_for_status()

        # Print the response
        print("[~] response.text:")
        print(response.text)

        sText = str(response.text)

        # ###

        sub_string = "User:"
        position = sText.find(sub_string)

        if position == -1:
            logging.error("User information not found in response")
            return None

        position = position + len(sub_string) + 1
        sTextWipOne = str(sText[position:])
        #print(sTextWipOne)
        # Split the response text by spaces
        lTextWipTwo = sTextWipOne.split(' ')
        sTextWipTwo = lTextWipTwo[0]
        print("[+] " + sub_string)
        print(sTextWipTwo)
        sReturn = sTextWipTwo
        return sReturn
    except requests.exceptions.RequestException as e:
        logging.error(f"AWS API request failed: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return None

def AWSAccount_from_AWSKeyID(AWSKeyID):
    
    trimmed_AWSKeyID = AWSKeyID[4:] #remove KeyID prefix
    x = base64.b32decode(trimmed_AWSKeyID) #base32 decode
    y = x[0:6]
    
    z = int.from_bytes(y, byteorder='big', signed=False)
    mask = int.from_bytes(binascii.unhexlify(b'7fffffffff80'), byteorder='big', signed=False)
    
    e = (z & mask)>>7
    return (e)

# print ("account id:" + "{:012d}".format(AWSAccount_from_AWSKeyID("ASIAQNZGKIQY56JQ7WML")))

def validate_string(input_string):
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    
    # Check if the string is exactly 20 characters long
    if len(input_string) != 20:
        return False
    
    # Check if the first 4 characters are letters
    if not input_string[:4].isalpha():
        return False
    
    # Check if all characters are valid
    if not all(char in valid_chars for char in input_string):
        return False
    
    return True

def keyid_to_username(sTextOne, sTextTwo):
    try:
        logging.info("Starting keyid_to_accountid function")
        #
        sAwsAccessKeyId = sTextOne.strip()
        sAwsSecretAccessKey = sTextTwo.strip()
        # Example usage
        #example_input = sText # "ASIAQNZGKIQY56JQ7WML"
        result = validate_string(sAwsAccessKeyId)
        print(f"Is '{sAwsAccessKeyId}' valid? {result}")
        #
        sResult = "!E55OR!"
        if result:
            resultOne = AWSAccount_from_AWSKeyID(sAwsAccessKeyId)
            sAwsAccountNumber = str("{:012d}".format(resultOne))
            print(f"Account ID: {sAwsAccountNumber}")
            resultTwo = AwsUsername_from_AwsCreds(sAwsAccessKeyId, sAwsSecretAccessKey)
            result = resultTwo
        else: 
            sResult = "Invalid Input :\\"
        sResult = str(result)
        #
        return sResult
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)
        return f"An unexpected error occurred: {str(e)}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AWS Key ID to Username converter')
    parser.add_argument('--accesskeyid', required=True, help='AWS Access Key ID (e.g., AKIA...)')
    parser.add_argument('--secretaccesskey', required=True, help='AWS Secret Access Key')
    
    args = parser.parse_args()
    
    logging.info("Starting script with provided credentials")
    result = keyid_to_username(args.accesskeyid, args.secretaccesskey)
    print(f"\nAWS IAM Username: {result}")