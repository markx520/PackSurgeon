#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import logging,time,os
from lib.common.utils import Utils


"""
1.from lib.common.CreatLog import creatLog
2._init_()里加入self.log = creatLog().get_logger()
3.self.log.debug("这里输入日志信息如api接口正常这样的")
4.self.log.info("这里输入print信息")
例如：
try:
    self.log.debug("正常输出信息")
except Exception as e:
    self.log.error("[Err] %s" %e)
需要使用日志记录的地方大致有一下几处：
    输入输出处，无论是从文件输入还是从网络等其他地方输入
    执行命令处
    调用函数处
"""

global log_name,logs #全局变量引用
global console_log_level

# 确保logs目录存在
logs_dir = "logs"
if not os.path.exists(logs_dir):
    try:
        os.makedirs(logs_dir)
    except Exception as e:
        print(f"[警告] 无法创建日志目录: {e}")

def _generate_task_tag():
    return Utils().creatTag(6)


def _build_log_name(task_tag):
    return logs_dir + os.sep + str(task_tag).strip() + ".log"


# 每次导入模块时生成首次任务上下文；后续任务可显式轮换。
logs = _generate_task_tag()
log_name = _build_log_name(logs)
# 控制台日志级别由主入口显式配置，避免在日志模块中再次解析命令行
console_log_level = logging.INFO


def configure_console_log_level(silent=None):
    """
    显式配置控制台日志级别。
    silent 非空时仅输出 ERROR，避免日志模块内部触发命令行解析副作用。
    """
    global console_log_level
    if silent is not None and str(silent).strip() != "":
        console_log_level = logging.ERROR
    else:
        console_log_level = logging.INFO


def start_new_task(task_tag=None):
    """
    轮换本次任务的 projectTag 与日志文件路径，并重置 root logger 的 handlers。
    这样同一进程内连续扫描多个目标时不会复用旧 tag / 旧日志文件。
    """
    global logs, log_name
    task_tag = str(task_tag or _generate_task_tag()).strip() or _generate_task_tag()
    logs = task_tag
    log_name = _build_log_name(task_tag)

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        try:
            root_logger.removeHandler(handler)
        except Exception:
            pass
        try:
            handler.close()
        except Exception:
            pass
    return logs


def get_current_task_tag():
    return logs


def get_current_log_name():
    return log_name


class creatLog():

    def __init__(self , logger=None):
        self.logger = logging.getLogger(logger)
        self.logger.setLevel(logging.NOTSET)
        self.log_time = time.strftime("%Y_%m_%d_")

    def info(self, message):
        self.fontColor('\033[0;34m%s\033[0m')
        self.logger.info(message)

    def set_logger(self):
        if not self.logger.handlers:
            try:
                # 再次确保logs目录存在（以防在多线程或特殊情况下目录被删除）
                logs_dir = os.path.dirname(log_name)
                if not os.path.exists(logs_dir):
                    os.makedirs(logs_dir)
                
                self.fh = logging.FileHandler(log_name, "w" ,encoding="utf-8")
                self.fh.setLevel(logging.DEBUG)
                self.chd = logging.StreamHandler()
                self.chd.setLevel(console_log_level)
                self.formatter = logging.Formatter(
                    "[%(levelname)s]--%(asctime)s-%(filename)s->%(funcName)s line:%(lineno)d: %(message)s\n")
                self.formatter_info = logging.Formatter()
                self.chd.setFormatter(self.formatter_info)
                self.fh.setFormatter(self.formatter)
                self.logger.addHandler(self.fh)
                self.logger.addHandler(self.chd)
            except Exception as e:
                # 如果创建日志文件失败，只使用控制台输出
                print(f"[警告] 无法设置文件日志: {e}")
                self.chd = logging.StreamHandler()
                self.chd.setLevel(logging.INFO)
                self.formatter_info = logging.Formatter()
                self.chd.setFormatter(self.formatter_info)
                self.logger.addHandler(self.chd)

    def get_logger(self):
        creatLog.set_logger(self)
        return self.logger

    def remove_log_handler(self):
        self.logger.removeHandler(self.fh)
        self.logger.removeHandler(self.chd)
        self.fh.close()
        self.chd.close()


# 命名兼容层：逐步过渡到规范类名，同时不破坏旧代码导入。
CreateLog = creatLog
