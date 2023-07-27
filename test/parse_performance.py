import json
import sys
import csv
from collect_performance import TestCase, test_case_list


class Matrices:
    min_cpu: float
    max_cpu: float
    avg_cpu: float
    min_mem: float
    max_mem: float
    avg_mem: float
    
    def __init__(self,
                 min_cpu: float = sys.float_info.max,
                 max_cpu: float = sys.float_info.min,
                 avg_cpu: float = 0,
                 min_mem: float = sys.float_info.max,
                 max_mem: float = sys.float_info.min,
                 avg_mem: float = 0
                 ):
        self.min_cpu = min_cpu
        self.max_cpu = max_cpu
        self.avg_cpu = avg_cpu
        self.min_mem = min_mem
        self.max_mem = max_mem
        self.avg_mem = avg_mem    
    
fs = False
fs_io = False

def parse_performance(test_case: TestCase):
    file_name = f"./data/{test_case.name}.json"
    with open(file_name, "r") as f:
        matrices = Matrices()
        ctx, cnt = json.load(f), 0
        
        for data in ctx:
            cpu_usage = data["cpu"]["usage"]["total"]
            mem_usage = data["memory"]["usage"]
            matrices.max_cpu = max(matrices.max_cpu, cpu_usage)
            matrices.min_cpu = min(matrices.min_cpu, cpu_usage)
            matrices.avg_cpu += cpu_usage
            matrices.max_mem = max(matrices.max_mem, mem_usage)
            matrices.min_mem = min(matrices.min_mem, mem_usage)
            matrices.avg_mem += mem_usage
            
            cnt += 1
        
        matrices.avg_cpu /= cnt
        matrices.avg_mem /= cnt
        
        global fs
        
        with open('./data/resource-util.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            
            if not fs:
                writer.writerow(["Test Case", 'nim_cpu', 'max_cpu', 'avg_cpu', 'min_mem', 'max_mem', 'avg_mem'])
                fs = True
            
            writer.writerow([test_case.name, matrices.min_cpu, matrices.max_cpu, matrices.avg_cpu, matrices.min_mem, matrices.max_mem, matrices.avg_mem])

        f.close()

def parse_io(test_case: TestCase):
    file_name = f"./data/{test_case.name}.txt"
    res = {}
    
    with open(file_name, "r") as f:
        lines, idx = f.readlines(), -1
        
        for i in range(len(lines)):
            
            if "Requests per second:    " in lines[i]:
                res['req_per_sec'] = lines[i].split(" ")[6]
            
            if "Percentage of the requests served within a certain time (ms)" in lines[i]:
                idx = i + 1
                break

        for line in lines[idx:]:
            if line.strip() == "":
                break
            
            parts = line.strip().split()
            percentage = parts[0].strip('%')
            time = int(parts[1])
            
            res[percentage] = time
    
    f.close()
    
    global fs_io
    
    with open('./data/io.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        
        if not fs_io:
            writer.writerow(["Test Case", 'P50', 'P66', 'P75', 'P80', 'P90', 'P95', 'P98', 'P99', 'P100', 'req_per_sec'])
            fs_io = True

        writer.writerow([test_case.name, res['50'], res['66'], res['75'], res['80'], res['90'], res['95'], res['98'], res['99'], res['100'], res['req_per_sec']]) 
    
    f.close()

if __name__ == "__main__":
    for test_case in test_case_list:
        parse_performance(test_case)
        parse_io(test_case)