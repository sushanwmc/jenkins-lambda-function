from pickle import NONE
import re
import psycopg2
import json
import itertools

from urllib.parse import urlparse
from elastic_search import ESConnection, EsQuery

# postgresql://postgres:Kitv2Loadtest!3@kit-v2-rds-postgres.c4f0vshw76xy.us-east-1.rds.amazonaws.com/loadtestkitv2

# Arora Read Only:
# postgresql://postgres:Kitv2Loadtest!3@kit-v2-readreplica-cluster.cluster-ro-c4f0vshw76xy.us-east-1.rds.amazonaws.com/loadtestkitv2

# Arora Read write
# kit-v2-readreplica-cluster.cluster-c4f0vshw76xy.us-east-1.rds.amazonaws.com
# postgresql://postgres:Kitv2Loadtest!3@kit-v2-readreplica-cluster.cluster-c4f0vshw76xy.us-east-1.rds.amazonaws.com/loadtestkitv2

#  Proxy read only
# postgresql://postgres:Kitv2Loadtest!3@kit-v2-aurora-read-only.endpoint.proxy-c4f0vshw76xy.us-east-1.rds.amazonaws.com/loadtestkitv2

# Proxy read write
# kit-v2-aurora.proxy-c4f0vshw76xy.us-east-1.rds.amazonaws.com


""" Configuration for Database """
result = urlparse(
    "postgresql://postgres:Kitv2Loadtest!3@kit-v2-readreplica-cluster.cluster-ro-c4f0vshw76xy.us-east-1.rds.amazonaws.com/loadtestkitv2")
# also in python 3+ use: urlparse("YourUrl") not urlparse.urlparse("YourUrl")
username = result.username
password = result.password
database = result.path[1:]
hostname = result.hostname
print("connecting to db")
conn = psycopg2.connect(
    database=database,
    user=username,
    password=password,
    host=hostname
)
print("Connection complete")
cur = conn.cursor()
""" End of Databse Configuration """


""" Configuration for Elastic Search """
index = "test-v2_kit_intel"
host = "https://localhost:9200/"
port = 9200
user = "kitintelloadtest"
password = 'vTRt:"5p#.4S$/b7'
""" End of Elastic Search config """


# Function to check wildcard


def check_wildcard(value):
    if "*" in value:
        value = value.replace("*", "%")
    return value

# Function to process json quer from user


def get_query_parameters(body_data):
    query_parms = {
        "content": body_data.get("content", None),
        "UUID": body_data.get("UUID") if body_data.get("UUID") else body_data.get('file.UUID', None),
        "filename": body_data.get("filename") if body_data.get("filename") else body_data.get('file.filename', None),
        "fullfilename": body_data.get("fullfilename") if body_data.get("fullfilename") else body_data.get('file.fu  llfilename', None),
        "filetype": body_data.get("filetype") if body_data.get("filetype") else body_data.get('file.filetype', None),
        "md5": body_data.get("md5") if body_data.get("md5") else body_data.get('file.md5', None),
        "sha256": body_data.get("sha256") if body_data.get("sha256") else body_data.get('file.sha256', None),
        "ssdeep": body_data.get("ssdeep") if body_data.get("ssdeep") else body_data.get('file.ssdeep', None),
        "modification_datetime_filter": body_data.get("datetime_filter", None),
        "kit.UUID": body_data.get("kit.UUID", None),
        "kit.kitname": body_data.get("kit.kitname", None),
        "kit.filetype": body_data.get("kit.filetype", None),
        "kit.md5": body_data.get("kit.md5", None),
        "kit.sha256": body_data.get("kit.sha256", None),
        "kit.ssdeep": body_data.get("kit.ssdeep", None),
        "kit.first_seen_filter": body_data.get("kit.first_seen_filter", None),
        "kit.last_seen_filter": body_data.get("kit.last_seen_filter", None),
        "page_size": body_data.get("page_size", 10),
        "search_id": body_data.get("search_id", None)

    }
    return query_parms


# Function to generate database query


def get_query_filter(filter_parms):
    query_filters = []

    # Generating query for UUID
    if filter_parms.get("UUID"):
        value = filter_parms.get("UUID")
        query = f"f.uuid like '{value}'"
        query_filters.append(query)

    # Generating query for filename
    if filter_parms.get("filename"):
        value = check_wildcard(filter_parms.get("filename"))
        if value.startswith("~"):
            value = value.lstrip("~")
            query = f"f.name ~ '{value}'"
        else:
            query = f"f.name ilike '{value}'"
        query_filters.append(query)

    # Generating query for fullfilename
    if filter_parms.get("fullfilename"):
        value = check_wildcard(filter_parms.get("fullfilename"))
        query = f"f.fullname ilike '{value}'"
        query_filters.append(query)

    # Generating query for filetype
    if filter_parms.get("filetype"):
        value = check_wildcard(filter_parms.get("filetype"))
        query = f"f.type ilike '{value}'"
        query_filters.append(query)

    # Generating query for Md5
    if filter_parms.get("md5"):
        value = filter_parms.get("md5")
        query = f"f.md5 like '{value}'"
        query_filters.append(query)

    # Generating query for sha256
    if filter_parms.get("sha256"):
        value = filter_parms.get("sha256")
        query = f"f.sha256 like '{value}'"
        query_filters.append(query)

    # Generating query for ssdeep
    if filter_parms.get("ssdeep"):
        value = filter_parms.get("ssdeep")
        query = f"f.ssdeep like '{value}'"
        query_filters.append(query)

     # Generating query for modification datetime
    if filter_parms.get("modification_datetime_filter"):
        value = filter_parms.get("modification_datetime_filter")
        from_date = value.get("from")
        to_date = value.get("to")
        query = f"f.modified_on between '{from_date}' and '{to_date}'"
        query_filters.append(query)

    # Generating query for kit UUID
    if filter_parms.get("kit.UUID"):
        value = filter_parms.get("kit.UUID")
        query = f"k.uuid like '{value}'"
        query_filters.append(query)

     # Generating query for  kitname
    if filter_parms.get("kit.kitname"):
        value = check_wildcard(filter_parms.get("kit.kitname"))
        query = f"k.name ilike '{value}'"
        query_filters.append(query)

     # Generating query for kit type
    if filter_parms.get("kit.filetype"):
        value = check_wildcard(filter_parms.get("kit.filetype"))
        query = f"k.type ilike '{value}'"
        query_filters.append(query)

    # Generating query for md5
    if filter_parms.get("kit.md5"):
        value = filter_parms.get("kit.md5")
        query = f"k.md5 like '{value}'"
        query_filters.append(query)

    # Generating query for kit sha256
    if filter_parms.get("kit.sha256"):
        value = filter_parms.get("kit.sha256")
        query = f"k.sha256 like '{value}'"
        query_filters.append(query)

    # Generating query for kit ssdeep
    if filter_parms.get("kit.ssdeep"):
        value = filter_parms.get("kit.ssdeep")
        query = f"k.ssdeep like '{value}'"
        query_filters.append(query)

    # Generating query for kit first_seen
    if filter_parms.get("kit.first_seen_filter"):
        value = filter_parms.get("kit.first_seen_filter")
        from_date = value.get("from")
        to_date = value.get("to")
        query = f"k.first_seen between '{from_date}' and '{to_date}'"
        query_filters.append(query)

    # Generating query for kit last_seen
    if filter_parms.get("kit.last_seen_filter"):
        value = filter_parms.get("kit.last_seen_filter")
        from_date = value.get("from")
        to_date = value.get("to")
        query = f"k.last_seen between '{from_date}' and '{to_date}'"
        query_filters.append(query)

    return query_filters


def process_data_to_json(k, all_data):
    kits = []
    for data in all_data:
        kit_exists = next(
            (item for item in kits if item["sha256"] == data[14]), False)
        if kit_exists:
            # print(kit_exists)
            pass
        else:
            kits.append({
                "kitname": [data[18]],
                "UUID": data[17],
                "md5": data[14],
                "ssdeep": data[15],
                "sha256": data[16],
                "size": data[19],
                "filetype": data[20],
                "first_seen_datetime": data[21].strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen_datetime": data[22].strftime("%Y-%m-%d %H:%M:%S")
            })

    json_data = {
        "file": {
            "filename": data[4],
            "filetype": data[3],
            "fullfilename": data[5],
            "ssdeep": data[6],
            "md5": data[7],
            "sha256": data[8],
            "UUID": data[9],
            "size": data[10],
            "modification_datetime": data[11].strftime("%Y-%m-%d %H:%M:%S")
        },
        "kits": kits
    }
    return json_data

# def get_search_id()


def lambda_handler(event, context):

    body = event.get("body", "")  # Query body from user
    total_count = None  # Initilazie total number of searched files
    search_id = None    # Initialize the search_id for pagination

    query_parms = get_query_parameters(json.loads(body))
    page_size = query_parms.pop("page_size")
    content = query_parms.pop("content")
    filters = get_query_filter(query_parms)

    if content:
        query = EsQuery()
        body = query.content_query(content="png")
        es = ESConnection(host=host, user=user, secret=password, port=port)
        res = es.search(index=index, body=body)
        uuids = []
        for data in res["hits"]["hits"]:
            uuids.append(data['_source']['UUID'])
        query = f"f.uuid in {tuple(uuids)}"
        filters.append(query)

    # Checking if filters exists
    if filters:
        # SELECT k.id as kit_id, f.id as file_id FROM PUBLIC.unique_files f INNER JOIN PUBLIC.unique_kits k ON f.id = k.id WHERE f.name ilike '%a%' LIMIT 10;
        # SELECT * FROM PUBLIC.unique_kits_unique_files ufk INNER JOIN PUBLIC.unique_kits k ON ufk.unique_kit_id = k.id INNER JOIN PUBLIC.unique_files f ON ufk.unique_file_id = f.id WHERE f.name ilike '%png' LIMIT 24;
        database_query = f"SELECT * FROM PUBLIC.unique_kits_unique_files ufk INNER JOIN PUBLIC.unique_files f ON ufk.unique_file_id = f.id INNER JOIN PUBLIC.unique_kits k ON ufk.unique_kit_id = k.id WHERE {' AND '.join(filters)} LIMIT 24"
        print(database_query)
    else:
        database_query = f"SELECT * FROM PUBLIC.unique_kits_unique_files ufk INNER JOIN PUBLIC.unique_files f ON ufk.unique_file_id = f.id INNER JOIN PUBLIC.unique_kits k ON ufk.unique_kit_id = k.id LIMIT 24"

    # Quering to database
    print("quering to databse")
    cur.execute(database_query)
    print("Query completed")
    # End of quering to database

    res_datas = cur.fetchall()

    # Process data from database response
    processed_datas = []
    count = 1
    for k, g in itertools.groupby(res_datas, lambda x: x[7]):
        if count <= page_size:
            uf = process_data_to_json(k, list(g))
            processed_datas.append(uf)
        else:
            break
        count += 1

    # Creating the json for response of API
    output_res = {
        "total_count": total_count,
        "page_count": len(processed_datas),
        "search_id": search_id,
        "results": processed_datas
    }

    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": '*'
        },
        "body": json.dumps(output_res)
    }


# query = EsQuery()
# body = query.content_query(content="png")
# es = ESConnection(host=host, user=user, secret=password, port=port)
# res = es.search(index=index, body=body)
# uuids = []
# for data in res["hits"]["hits"]:
#     uuids.append(data['_source']['UUID'])
# query = f"SELECT * FROM PUBLIC.unique_kits_unique_files ufk INNER JOIN PUBLIC.unique_files f ON ufk.unique_file_id = f.id INNER JOIN PUBLIC.unique_kits k ON ufk.unique_kit_id = k.id WHERE f.uuid in {tuple(uuids)} LIMIT 24;"
# # print(uuids)
# # print(query)
# cur.execute(query)
# res_datas = cur.fetchall()
# print(res_datas)


event = {'resource': '/', 'path': '/', 'httpMethod': 'POST', 'headers': None, 'multiValueHeaders': None, 'queryStringParameters': None, 'multiValueQueryStringParameters': None, 'pathParameters': None, 'stageVariables': None, 'requestContext': {'resourceId': 't3wsn1efl3', 'resourcePath': '/', 'httpMethod': 'POST', 'extendedRequestId': 'FPAXzFfTIAMF60Q=', 'requestTime': '06/Sep/2021:09:35:58 +0000', 'path': '/', 'accountId': '851797349069', 'protocol': 'HTTP/1.1', 'stage': 'test-invoke-stage', 'domainPrefix': 'testPrefix', 'requestTimeEpoch': 1630920958511, 'requestId': '3b85ab85-f3c0-46f5-8358-353d73f71bc1', 'identity': {'cognitoIdentityPoolId': None, 'cognitoIdentityId': None, 'apiKey': 'test-invoke-api-key', 'principalOrgId': None, 'cognitoAuthenticationType': None, 'userArn': 'arn:aws:iam::851797349069:user/ayush.jha@fusemachines.com', 'apiKeyId': 'test-invoke-api-key-id', 'userAgent': 'aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.129-72.229.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.302-b08 java/1.8.0_302 vendor/Oracle_Corporation cfg/retry-mode/legacy', 'accountId': '851797349069', 'caller': 'AIDA4MUYUCLG4A5X6DTBX', 'sourceIp': 'test-invoke-source-ip', 'accessKey': 'ASIA4MUYUCLGZFVTGRN4', 'cognitoAuthenticationProvider': None, 'user': 'AIDA4MUYUCLG4A5X6DTBX'}, 'domainName': 'testPrefix.testDomainName', 'apiId': 'b672r6l7ch'},
         'body': '{"content":"png", "page_size":1}',
         'isBase64Encoded': False}
res = lambda_handler(event, None)
print(res)

# "modification_datetime_filter":{"from":"2022-07-01 16:46:11", "to":"2022-08-20 16:46:11"}
