from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python_operator import PythonOperator
from airflow.sensors.filesystem import FileSensor
import subprocess

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'start_date': datetime(2023, 5, 24),
    'retries': 1,
    'retry_delay': timedelta(minutes=5)
}

dag = DAG(
    'execute_test_script',
    default_args=default_args,
    description='Execute test.py when a file is added with a new line',
    schedule_interval=None  # Set to None to disable scheduling
)

def execute_test_script():
    subprocess.run(["python3", "/Users/dexter/Desktop/GitHub/Honeypot-Project/src/airflow/extraction.py"])

file_sensor_task = FileSensor(
    task_id='file_sensor_task',
    poke_interval=10,
    filepath='/Users/dexter/Desktop/GitHub/Honeypot-Project/src/waf-honeypots/logs/modsec3-nginx/access.log',
    dag=dag
)

execute_script_task = PythonOperator(
    task_id='execute_script_task',
    python_callable=execute_test_script,
    dag=dag
)

file_sensor_task >> execute_script_task