# printer_client/src/client.py

import requests
from config import load_config

def register_with_data_center(config):
    # 将当前3D打印设备注册至数据处理中心
    response = requests.post(config['data_center_url'] + '/register', json=config)
    return response.status_code == 200

def report_task_completion(task_id, config):
    # Report the completion of a task to the data center
    response = requests.post(config['data_center_url'] + '/task', json={'id': task_id, 'status': 'completed'})
    return response.status_code == 200

def main():
    # 加载打印设备配置
    config = load_config('/config/printer.json')

    # 注册至数据处理中心
    if register_with_data_center(config):
        print("Register successful.")
        # Upon successful registration, get a task and process it
        # Once complete, report back to data center
        task_id = "task12345"  # This should actually be received from the data center
        if report_task_completion(task_id, config):
            print(f"Task {task_id} reported as complete successfully.")
    else:
        print("Failed to register with the data center.")

if __name__ == '__main__':
    main()
