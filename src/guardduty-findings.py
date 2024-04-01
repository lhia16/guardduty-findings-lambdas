import os, uuid, boto3, json, urllib3
from datetime import datetime, timezone 

gd = boto3.client('guardduty')
detector = gd.list_detectors()
ddb = boto3.client('dynamodb')
detectorid = detector['DetectorIds'][0]
http = urllib3.PoolManager()
table_name = os.environ['TABLE_NAME']
ssm = boto3.client('ssm')
parameter = ssm.get_parameter(Name='/guardduty/prod/slack', WithDecryption=True)['Parameter']['Value']

def get_lowfindings(gd,detectorid):
    lowFC = {'Criterion': {'severity': {'Lte': 4}}}
    lowFindings = len(gd.list_findings(DetectorId=detectorid,FindingCriteria=lowFC)['FindingIds'])
    return(lowFindings)
def get_mediumfindings(gd,detectorid):
    mediumFC = {'Criterion': {'severity': {'Gte': 4, 'Lt': 7}}}
    mediumFindings = len(gd.list_findings(DetectorId=detectorid,FindingCriteria=mediumFC)['FindingIds'])
    return(mediumFindings)
def get_highfindings(gd,detectorid):
    highFC = {'Criterion': {'severity': {'Gte': 7}}}
    highFindings = len(gd.list_findings(DetectorId=detectorid,FindingCriteria=highFC)['FindingIds'])
    return(highFindings)
    
        
def update_dynamo(HIGH,MEDIUM,LOW,dynamodb=None):
    dt = datetime.now() 
    local_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    reportuuid = uuid.uuid1()
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', endpoint_url="http://dynamodb.eu-west-2.amazonaws.com")
    table = dynamodb.Table(table_name)
    response = table.put_item(
         Item=
         {
          "ID": str(reportuuid),
          "DateCreated": str(local_time),
          "Detector": {
            "IncidentMedium":MEDIUM ,
            "IncidentHigh": HIGH,
            "IncidentLow": LOW
           },
          "DetectorID": detectorid
        
         }
     )

    return reportuuid


def lambda_handler(event, context):
   
    lowFindings=get_lowfindings(gd,detectorid)
    mediumFindings=get_highfindings(gd,detectorid)
    highFindings=get_highfindings(gd,detectorid)
    
    reportuuid=str(update_dynamo(highFindings,mediumFindings,lowFindings))

    
    message = f"*Security Findings*\n\nHigh Severity : {highFindings}\nMedium Severity : {mediumFindings}\nLow Severity: {lowFindings}\n"
    data = {
    "blocks": [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Hello, this is an automated daily PCI Security and Performance report\n\n *Please Review and Acknowledge:*"
            }
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": message
            }
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Are you happy to acknowledge these findings?"
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Acknowledge"
                },
                "value": reportuuid
            }
        }
    ]
}
    r = http.request("POST",
                    f"{parameter}",
                    body = json.dumps(data),
                    headers = {"Content-type": "application/json"})


