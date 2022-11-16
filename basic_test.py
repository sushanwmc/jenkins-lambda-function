import requests
import json
from jsonschema import validate
from jsonschema import Draft6Validator
from function import lambda_handler

url = "https://api.phishfeed.com/KIT/v1/search/"
payload = json.dumps({
    "kit.sha256": "c479e903173516e4d3d4795cec2ca2e9366c61982600ac51efee7d6fd14d51f9",
    "page_size": 1,
    "filter": ["UUID", "filename"]
})
headers = {
    'x-api-key': 'uCu0HTsa0M6xuDf9b7JI43AO1nJ7zHwvuiwexbW8',
    'Content-Type': 'application/json'
}

schema = {
    "type": "object",
    "properties": {
        "total_count": {"type": "number"},
        "page_count": {"type": "number"},
        "scroll_id": {
            "type": "string",
            "contains": {"type": "number"}
        },
        "results": {"type": "array"}
    }
}

# {
#     "type": "object",
#             "properties": {
#                 "id": {"type": "string"},
#                 "firstName": {"type": "string"},
#                 "middleName": {
#                     "anyOf": [
#                         {"type": "string"},
#                         {"type": "null"}
#                     ]},
#                 "lastName": {"type": "string"}
#             },
#     "required": ["id", "firstName", "lastName"]
# }


# def test_post_search_check_status_code_equals_200():
#     response = requests.request("POST", url, headers=headers, data=payload)
#     assert response.status_code == 200


# def test_post_search_validates_json_response_schema():
#     response = requests.request("POST", url, headers=headers, data=payload)
#     assert response.status_code == 200
#     assert response.headers["Content-Type"] == "application/json"
#     resp_body = response.json()
#     validate(instance=resp_body, schema=schema)


event = {'resource': '/', 'path': '/', 'httpMethod': 'POST', 'headers': None, 'multiValueHeaders': None, 'queryStringParameters': None, 'multiValueQueryStringParameters': None, 'pathParameters': None, 'stageVariables': None, 'requestContext': {'resourceId': 't3wsn1efl3', 'resourcePath': '/', 'httpMethod': 'POST', 'extendedRequestId': 'FPAXzFfTIAMF60Q=', 'requestTime': '06/Sep/2021:09:35:58 +0000', 'path': '/', 'accountId': '851797349069', 'protocol': 'HTTP/1.1', 'stage': 'test-invoke-stage', 'domainPrefix': 'testPrefix', 'requestTimeEpoch': 1630920958511, 'requestId': '3b85ab85-f3c0-46f5-8358-353d73f71bc1', 'identity': {'cognitoIdentityPoolId': None, 'cognitoIdentityId': None, 'apiKey': 'test-invoke-api-key', 'principalOrgId': None, 'cognitoAuthenticationType': None, 'userArn': 'arn:aws:iam::851797349069:user/ayush.jha@fusemachines.com', 'apiKeyId': 'test-invoke-api-key-id', 'userAgent': 'aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.129-72.229.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.302-b08 java/1.8.0_302 vendor/Oracle_Corporation cfg/retry-mode/legacy', 'accountId': '851797349069', 'caller': 'AIDA4MUYUCLG4A5X6DTBX', 'sourceIp': 'test-invoke-source-ip', 'accessKey': 'ASIA4MUYUCLGZFVTGRN4', 'cognitoAuthenticationProvider': None, 'user': 'AIDA4MUYUCLG4A5X6DTBX'}, 'domainName': 'testPrefix.testDomainName', 'apiId': 'b672r6l7ch'},
         'body': '{"content":"png", "page_size":1}',
         'isBase64Encoded': False}


def test_lambda_handler():
    response = lambda_handler(event, None)
    assert response["statusCode"] == 400
