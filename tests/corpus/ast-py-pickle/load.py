import pickle, json
blob = request.data
data = pickle.loads(blob)
ok = json.loads(blob)
