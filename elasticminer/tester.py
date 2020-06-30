from elasticsearch import Elasticsearch

es = Elasticsearch(['http://10.8.33.129:9200', 'http://10.8.33.130:9200', 'http://localhost:9200'],
                   http_auth=('logstash_user', 'Sedoc2018!'), request_timeout=60)

query = {
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.detail": "Sign-in was blocked because it came from an IP address with malicious activity."
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-100d/d",
                            "lte": "now"
                        }
                    }
                }
            ]
        }
    }
}

es_docs = es.search(index='ecs-office365-*', body=query, request_timeout=60, size=100000)['hits']['hits']

prova = es_docs[0]
string = "_source']['" + "event.detail".replace(".", "']['")
prova2 = eval("prova['{}']".format(string))

print('ciao')
print('ciao')
print('ciao')
