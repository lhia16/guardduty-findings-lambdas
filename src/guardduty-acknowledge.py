import os, uuid, boto3, json, urllib3, base64, urllib.parse
from datetime import datetime, timezone 

http = urllib3.PoolManager()
ssm = boto3.client('ssm')
parameter = ssm.get_parameter(Name='/guardduty/prod/slack', WithDecryption=True)['Parameter']['Value']
table_name = os.environ['TABLE_NAME']

def lambda_handler(event, context):
     response = base64.b64decode(event['body']).decode('utf-8')
     body = (urllib.parse.unquote(response)).strip("payload=")
     username = ((json.loads(body))["user"]["username"])
     reportuuid = ((json.loads(body))["message"]["blocks"][4]["accessory"]["value"])
     responseurl = ((json.loads(body))["response_url"])
 
     # if username, reportuuid:
     add_user_acknowledgement(username, reportuuid)
     
     format_name = username.split(".")[0].capitalize()
     message = f"Thank you {format_name}"
     data = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
    
            }   
        ]
    } 
     r = http.request("POST",
                     f"{parameter}",
                      body = json.dumps(data),
                      headers = {"Content-type": "application/json"})
  
     
def add_user_acknowledgement(username, reportuuid, dynamodb=None):
     dt = datetime.now() 
     local_time = dt.strftime("%Y-%m-%d %H:%M:%S")
     
     if not dynamodb:
          dynamodb = boto3.resource('dynamodb', endpoint_url="http://dynamodb.eu-west-2.amazonaws.com")
     table = dynamodb.Table(table_name)
     response = table.update_item(
        Key={
             'ID': reportuuid
             
        },
        UpdateExpression="set DateAcknowledged=:date_ack, UserName=:name",
        ExpressionAttributeValues={
               ':date_ack': local_time,
               ':name': username
             
        },
        ReturnValues="UPDATED_NEW"
     
    )
     return response
