import httplib2
import json
import time
import arrow
from datetime import datetime, timedelta
from api_auth import sign_request, sign_request_full

if __name__ == '__main__':

    httplib2.debuglevel = 0
    http = httplib2.Http()
    content_type_header = "application/json"

    impostor_key = 'de9ca96e-3ae0-4a9c-9bf3-a358fb654727'  # An impostor key!
    private_key = 'eb886203-0876-44f0-871d-6dd02fee3abb'
    api_key = 'b3333e7d-0c4d-477a-8c2d-a7b0a9fbe25f'
    uri = "/api/v1.0/"
    url = "http://127.0.0.1:5000%s" % uri

    data = {'room': "Living Room",
            'temp': 23.45,
            'humidity': 50.00,
            'timestamp': str(datetime.now())
            }

    print ("Posting Data with correct MAC" % data)

    claim_text, signature = sign_request(uri, api_key, private_key)
    headers = {'Content-Type': content_type_header,
               'x-api-claim': claim_text,
               'x-api-mac': signature
               }

    response, content = http.request(url,
                                     'POST',
                                     json.dumps(data),
                                     headers=headers)
    print (response)
    print (content)
    time.sleep(3)

    print ("Posting Data with incorrect timestamp" % data)

    incorrect_time = datetime.utcnow() + timedelta(minutes=1)
    timestamp = arrow.get(incorrect_time).timestamp
    claim_text, signature = sign_request_full(uri, api_key, timestamp, 'asdpfoiasug98', private_key)
    headers = {'Content-Type': content_type_header,
               'x-api-claim': claim_text,
               'x-api-mac': signature
               }

    response, content = http.request(url,
                                     'POST',
                                     json.dumps(data),
                                     headers=headers)
    print (response)
    print (content)
    time.sleep(3)

    print ("Posting Data with incorrect uri" % data)

    timestamp = arrow.get(datetime.utcnow()).timestamp
    claim_text, signature = sign_request_full('/some/wack/api/uri/', api_key, timestamp, 'asdfha0s7g8', private_key)
    headers = {'Content-Type': content_type_header,
               'x-api-claim': claim_text,
               'x-api-mac': signature
               }

    response, content = http.request(url,
                                     'POST',
                                     json.dumps(data),
                                     headers=headers)
    print (response)
    print (content)
    time.sleep(3)

    print ("Posting Data with incorrect private key" % data)

    timestamp = arrow.get(datetime.utcnow()).timestamp
    claim_text, signature = sign_request(uri, api_key, impostor_key)
    headers = {'Content-Type': content_type_header,
               'x-api-claim': claim_text,
               'x-api-mac': signature
               }

    response, content = http.request(url,
                                     'POST',
                                     json.dumps(data),
                                     headers=headers)
    print (response)
    print (content)
