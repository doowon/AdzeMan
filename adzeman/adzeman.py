import base64
import json
import math
import os
from datetime import datetime
from collections import deque

import argparse
import asyncio
from os import write
from re import sub
import aiohttp
import aiofiles
import aioprocessing
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

import requests
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionOID
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

import certstruct

ct_log_info_url = "https://{}/ct/v1/get-sth" 
ct_log_down_url = "https://{}/ct/v1/get-entries?start={}&end={}"
CONCURRENCY_CNT = 2
MAX_QUEUE_SIZE = 2000
MAX_CSV_SAVE_FILE_NUM = 1000000

def get_max_block_size(ct_url):
    """
    Return the size of max block
    
    RFC 6962: Logs MAY restrict the number of entries that can be retrieved per
    "get-entries" request.  If a client requests more than the permitted
    number of entries, the log SHALL return the maximum number of entries
    permissible.  These entries SHALL be sequential beginning with the
    entry specified by "start"
    """
    r = requests.get(ct_log_down_url.format(ct_url, 0, 100000))
    if r.status_code == 200:
        return len(r.json()["entries"])
    else: 
        raise Exception("Failed in retrieving CT log info.")

def get_tree_size(ct_url):
    r = requests.get(ct_log_info_url.format(ct_url))
    if r.status_code == 200:
        ct_info = r.json()
        return int(ct_info["tree_size"])
    else:
        raise Exception("Failed in retrieving CT log info.")

def retrieve_all_ct_logs():
    """
    Retreive all CT logs
    The list of CT Logs that are currently compliant with Chrome's CT policy (or have been and were disqualified), and are included in Chrome:
    "https://www.gstatic.com/ct/log_list/v2/log_list.json"
    """
    total_cert_num = 0
    all_ct_logs_url = "https://www.gstatic.com/ct/log_list/v2/log_list.json"
    r = requests.get(all_ct_logs_url)
    if r.status_code == 200:
        for info in r.json()["operators"]:
            for log in info["logs"]:
                if "usable" not in log["state"]:
                    continue
                r = requests.get(ct_log_info_url.format(log['url']))
                if r.status_code == 200:
                    ct_info = r.json()
                    tree_size = ct_info["tree_size"]
                    total_cert_num += tree_size
                    timestamp = datetime.fromtimestamp(int(ct_info["timestamp"])/1000.0)
                else:
                    tree_size = -1
                    timestamp = 0
                print(log['description'])
                print("\t\- URL:\t\t\t{}".format(log['url']))
                print("\t\- Operator:\t\t{}".format(info['name']))
                print("\t\- Cert. Count:\t\t{}".format(tree_size))
                print("\t\- Timestamp:\t\t{}".format(timestamp.strftime('%Y-%m-%d %H:%M:%S')))
                print("\t\- Max Block Size:\t{}\n".format(get_max_block_size(log['url'])))
    
    print("Total Cert. number:", total_cert_num)

def get_all_domains(cert):
    """
    Get all domains in a certificate
    """

    all_domains = set()

    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for attr in attrs:
            all_domains.add(attr.value)
    except:
        pass
    
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        alt_names = ext.value.get_values_for_type(x509.DNSName)
        all_domains.update(alt_names)
    except: # in case where alternative names do not exist
        pass

    return list(all_domains)


def parse_ct_cert(entry):
    """
    In this program, it does not parse precertificates
    if precertificates, return None
    """
    cert_data = certstruct.CertData()

    leaf_input = entry["leaf_input"]
    mth = certstruct.MerkleTreeHeader.parse(base64.b64decode(leaf_input))
    
    cert_data.log_timestamp = mth.Timestamp
    
    if mth.LogEntryType == "X509LogEntryType":
        cert = x509.load_der_x509_certificate(certstruct.Certificate.parse(mth.Entry).CertData, default_backend())
        cert_data.all_domains = get_all_domains(cert)
        
        #not before and not after
        cert_data.not_before = int(datetime.timestamp(cert.not_valid_before))
        cert_data.not_after = int(datetime.timestamp(cert.not_valid_after))

        #dump cert in byte
        cert_data.cert_dump = base64.b64encode(cert.public_bytes(Encoding.DER)).decode('utf-8')

        return cert_data
    else: # if Log entry type is precertificate
        return None

def populate_work(work_deque, max_block_size, tree_size, csv_save_root_path, start_ct_index=0):
    """
    tree_size -- the total number of certificates
    """
    print("Populating works...")
    
    # Resume feature: check the downloaded last start_ct_index in the download directory
    # and populate undownloaded ct entiries.
    downloaded_csv_files = set()
    for subdir in os.listdir(csv_save_root_path):
        for csv_file in os.listdir(os.path.join(csv_save_root_path, subdir)):
            downloaded_csv_files.add(int(csv_file.split("-")[0]))

    total_size = tree_size - 1
    end_ct_index = start_ct_index + max_block_size - 1

    if end_ct_index >= total_size:
        end_ct_index = total_size
    
    if start_ct_index == (tree_size - 1):
        raise Exception("No work!")

    all_start_number_list = set()
    while True:
        all_start_number_list.add(start_ct_index)
        
        if end_ct_index >= total_size:
            end_ct_index = total_size
            break
        
        start_ct_index = end_ct_index + 1
        end_ct_index = start_ct_index + max_block_size

    to_down_start_idx = all_start_number_list - downloaded_csv_files

    digit = len(str(MAX_CSV_SAVE_FILE_NUM)) - 1
        
    for start_idx in sorted(list(to_down_start_idx)):
        if start_idx < MAX_CSV_SAVE_FILE_NUM:
            subdir = "0"
        else:
            subdir = str(start_idx)[:-digit]
        csv_save_subdir_path = os.path.join(csv_save_root_path, subdir)
        if not os.path.exists(csv_save_subdir_path):
            os.makedirs(csv_save_subdir_path, exist_ok=True)
        
        end_idx = start_idx + max_block_size
        if end_idx >= total_size:
            end_idx = total_size
        
        work_deque.append((start_idx, end_idx, csv_save_subdir_path))
        # print(start_idx, end_idx, csv_save_subdir_path)
    
    print("All block nubmer to download: {}, Downloaded block number: {}, To download block number: {}".format(
        len(all_start_number_list),
        len(downloaded_csv_files),
        len(to_down_start_idx)
    ))
    print("All work queue size:", len(work_deque))

async def download_entiries_work(loop, work_deque, ct_url, parse_que, fail_csv_path):
    async with aiohttp.ClientSession(loop=loop, timeout=aiohttp.ClientTimeout(total=10)) as session:
        while True:
            try:
                start_ct_index, end_ct_index, csv_save_subdir_path = work_deque.popleft()
            except Exception as e:
                print(e)
                return
            
            async with session.get(ct_log_down_url.format(ct_url, start_ct_index, end_ct_index)) as response:
                if response.status == 200:
                    j_data = await response.json()
                    entries = j_data["entries"]
                    csv_save_file_name = "{}-{}.csv".format(start_ct_index, end_ct_index)
                    csv_save_file_path = os.path.join(csv_save_subdir_path, csv_save_file_name)
                    await parse_que.put({
                        "ct_url": ct_url,
                        "entries": entries,
                        "csv_save_file_path": csv_save_file_path,
                        "start_ct_index": start_ct_index,
                        "end_ct_index": end_ct_index
                    })
                else:
                    async with aiofiles.open(os.path.join(fail_csv_path, "fail.csv"), "a") as f:
                        await f.write("{}, {}, {}\n".format(ct_url, start_ct_index, end_ct_index))
            # await asyncio.sleep(2)

def parse_worker(entries):
    """
    Parse x509 and save it in CSV
    """
    lines = []
    start_ct_index = entries["start_ct_index"]
    csv_save_file_path = entries["csv_save_file_path"]

    i = 0
    for entry in entries["entries"]:
        cert_data = parse_ct_cert(entry)
        if cert_data is None:
            continue
        lines.append(
            ",".join([
                ct_url,
                str(start_ct_index + i),
                str(cert_data.log_timestamp),
                " ".join(cert_data.all_domains),
                str(cert_data.not_before),
                str(cert_data.not_after),
                cert_data.cert_dump
            ]) + "\n"
        )
        i += 1
    
    print("pid", os.getpid(), start_ct_index)
    
    with open(csv_save_file_path, "w", encoding="UTF-8") as f:
        f.write("".join(lines))

async def parse_entiries_work(parse_que: asyncio.Queue):
    
    process_pool = aioprocessing.AioPool()

    while True:
        entries_list = []
        for _ in range(int(process_pool.pool_workers)):
            entries = await parse_que.get()
            if entries != None:
                entries_list.append(entries)
        
        if len(entries_list) > 0:
            await process_pool.coro_map(parse_worker, entries_list)
    
    process_pool.close()
    await process_pool.coro_join()
            
async def work_queue_monitor(work_deque: deque, parse_que: asyncio.Queue, total_block_size):
    while True:
        print("Queue Status: Parse Queue Size: {}, Downloaded blocks: {}/{} ({:.4f}%)".format(
            parse_que.qsize(),
            total_block_size - len(work_deque),
            total_block_size,
            ((total_block_size - len(work_deque)) / total_block_size) * 100.0
        ))
        print(len(work_deque))
        await asyncio.sleep(2)

async def retrieve_certs(loop, ct_url, start_ct_index=0, down_dir="/tmp/", concurrency_cnt=CONCURRENCY_CNT): 

    try:
        max_block_size = get_max_block_size(ct_url)
        tree_size = get_tree_size(ct_url)
    except Exception as e:
        print(e)
        return

    csv_save_root_path ='{}/certificates/{}'.format(down_dir, ct_url.replace('/', '_'))
    if not os.path.exists(csv_save_root_path):
        os.makedirs(csv_save_root_path, exist_ok=True)

    # populate work loads and insert them into deque
    try:
        work_deque = deque()
        populate_work(work_deque, max_block_size, tree_size, csv_save_root_path, start_ct_index)
        print("Downloading certificates from CT", ct_url)
        print(("Total: {}, start_ct_index: {}, # of chunks: {}".format(tree_size, start_ct_index, len(work_deque))))
        chunk_size = len(work_deque)
    except Exception as e:
        print(e)
        return
    
    parse_que = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
    
    monitor_task = asyncio.create_task(work_queue_monitor(work_deque, parse_que, chunk_size))

    for _ in range(concurrency_cnt):
        asyncio.create_task(download_entiries_work(loop, work_deque, ct_url, parse_que, down_dir))
        
    asyncio.create_task(parse_entiries_work(parse_que))
    
    await monitor_task

    # await parse_que.join()
    # indicate the producer is done
    await parse_que.put(None)

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description='Download Certificate Transparency Logs')
    # retrieve_all_ct_logs()
    
    # ct_url = "ct.googleapis.com/rocketeer"
    ct_url = "oak.ct.letsencrypt.org/2021"
    if "https://" in ct_url:
        ct_url = ct_url.replace("https://", "")
    elif "http://" in ct_url:
        ct_url = ct_url.replace("http://", "")
    
    start_ct_index = 0
    loop = asyncio.get_event_loop()
    loop.run_until_complete(retrieve_certs(loop, ct_url, start_ct_index))
    loop.close()

    # work_deque = deque()
    # populate_work(work_deque, 10, 100)
