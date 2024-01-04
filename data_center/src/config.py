# 共享代码片段，可用于数据中心及客户端
import json

def load_config(config_path):
    with open(config_path) as config_file:
        return json.load(config_file)
