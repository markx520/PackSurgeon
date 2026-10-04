# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
命名兼容模块:
- 新代码建议从 lib.common.create_log 导入
- 旧代码仍可继续使用 lib.common.CreatLog
"""

from lib.common.CreatLog import (  # noqa: F401
    creatLog,
    CreateLog,
    logs,
    log_name,
    configure_console_log_level,
    start_new_task,
    get_current_task_tag,
    get_current_log_name,
)

