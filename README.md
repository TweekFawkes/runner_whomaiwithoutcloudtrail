# WhoAmi Without CloudTrail Logging

This Leverages an AWS API Endpoint for SQS with the Action of ListQueues, which lacks CloudTrail logging as of 20240708 and returns the username associated with the credentials as part of the error messaging that is return from the api endpoint when the user does not have access to the SQS service. See the AWS docs and references below for more information.
