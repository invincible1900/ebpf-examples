#!/usr/bin/env python3
import json
import os
with open("sym.json", 'rb') as f:
	sym = json.load(f);

with open("fentry.bpf.c", 'rb') as f:
	data = f.read();

data = data.replace(b'[NAME]', sym["name"].encode());
data = data.replace(b'[ARGS]', sym["args"].encode());
data = data.replace(b'[TYPE]', sym["type"].encode());

with open("fentry.bpf.c", 'wb') as f:
	f.write(data)

os.system("make")
