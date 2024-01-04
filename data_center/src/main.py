# data_center/src/main.py

from dpu import DPUManager
from config import load_config
from flask import Flask, request

app = Flask(__name__)

# 加载数据处理中心配置
config = load_config('/config/data_center.json')

# 初始化并配置DPU管理器
dpu_manager = DPUManager(config)


@app.route('/register', methods=['POST'])
def register_machine():
    device_info = request.get_json()
    if device_info:
        response = dpu_manager.register_device(device_info)
        return {'status': 'success', 'message': response}, 200
    return {'status': 'error', 'message': 'Invalid data received'}, 400


@app.route('/task', methods=['POST'])
def receive_task():
    task_info = request.get_json()
    if task_info:
        response = dpu_manager.process_task(task_info)
        return {'status': 'success', 'message': response}, 200
    return {'status': 'error', 'message': 'Invalid task information'}, 400

    
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
